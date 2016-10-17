/* ====================================================================
 * The Kannel Software License, Version 1.0
 *
 * Copyright (c) 2001-2010 Kannel Group
 * Copyright (c) 1998-2001 WapIT Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Kannel Group (http://www.kannel.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Kannel" and "Kannel Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please
 *    contact org@kannel.org.
 *
 * 5. Products derived from this software may not be called "Kannel",
 *    nor may "Kannel" appear in their name, without prior written
 *    permission of the Kannel Group.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE KANNEL GROUP OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Kannel Group.  For more information on
 * the Kannel Group, please see <http://www.kannel.org/>.
 *
 * Portions of this software are based upon software originally written at
 * WapIT Ltd., Helsinki, Finland for the Kannel project.
 */

/*
 * smpp_client.c
 *
 * This is the core module of the smppclient.
 *
 * Dimitrios Bouzikas <dimimpou@gmail.com> 2015
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "gwlib/gwlib.h"
#include "msg.h"
#include "smpp_client.h"
#include "shared.h"
#include "load.h"

#include "smsc/smpp_pdu.h"
#include "gwlib/json.h"

/* configuration filename */
Octstr *cfg_filename;

/* Path to storage folder needed for configuration */
Octstr *store_location;

volatile sig_atomic_t client_status;

/* own global variables */

static Mutex *status_mutex;
static time_t start_time;

int fd_smpp_connect;
static int conn_ready = 0;

static SMSCConn *conn;
static Octstr *smpp_status = NULL;
Counter *split_msg_counter;

/*-------------------------------------------------------
 * signals
 */

static void signal_handler(int signum)
{
	/* On some implementations (i.e. linuxthreads), signals are delivered
	 * to all threads.  We only want to handle each signal once for the
	 * entire box, and we let the gwthread wrapper take care of choosing
	 * one.
	 */
	if (!gwthread_shouldhandlesignal(signum))
		return;
	
	switch (signum) {
		case SIGINT:
		case SIGTERM:
			if (client_status != SHUTDOWN && client_status != DEAD) {
				client_status = SHUTDOWN;
			}
			else if (client_status == SHUTDOWN) {
				client_status = DEAD;
			}
			else if (client_status == DEAD) {
				panic(0, "Cannot die by its own will");
			}
			break;
			
		case SIGHUP:
			log_reopen();
			alog_reopen();
			break;
			
			/*
			 * It would be more proper to use SIGUSR1 for this, but on some
			 * platforms that's reserved by the pthread support.
			 */
		case SIGQUIT:
			warning(0, "SIGQUIT received, reporting memory usage.");
			gw_check_leaks();
			break;
	}
}

static void setup_signal_handlers(void)
{
	struct sigaction act;
	
	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
}

static Cfg *init_client(Cfg *cfg)
{
	Octstr *log;
	CfgGroup *grp;
	long loglevel;
	
	grp = cfg_get_single_group(cfg, octstr_imm("core"));
	
	log = cfg_get(grp, octstr_imm("log-file"));
	if (log != NULL) {
		if (cfg_get_integer(&loglevel, grp, octstr_imm("log-level")) == -1)
			loglevel = 0;
		log_open(octstr_get_cstr(log), loglevel, GW_NON_EXCL);
		octstr_destroy(log);
	}
	
	store_location = cfg_get(grp, octstr_imm("store-location"));
	
	status_mutex = mutex_create();
	
	setup_signal_handlers();
	
	httpadmin_start(cfg);
	
	return cfg;
}

static Octstr *set_error_and_status(int error, const char *status)
{
	Octstr *reply;
	JSON_Object *reply_object;
	JSON_Value  *root_value;
	char *json_reply = NULL;
	
	root_value = json_value_init_object();
	reply_object = json_value_get_object(root_value);
	
	json_object_set_number(reply_object, "error", error);
	json_object_set_string(reply_object, "version", status);
	json_object_set_string(reply_object, "status", status);
	json_object_set_string(reply_object, "uptime", status);
	json_reply = json_serialize_to_string_pretty(root_value);
	
	reply = octstr_create(json_reply);
	json_free_serialized_string(json_reply);
	json_value_free(root_value);
	
	return reply;
}

Octstr *print_status(List *cgivars, int status_type)
{
	char *s;
	Octstr *reply, *uptime, *version;
	
	JSON_Object *reply_object;
	JSON_Value  *root_value;
	char *json_reply = NULL;
	
	time_t t;
	
	t = time(NULL) - start_time;
	
	if (client_status == RUNNING)
		s = "running";
	else
		s = "shutting down";
	
	root_value = json_value_init_object();
	reply_object = json_value_get_object(root_value);
	
	version = version_report_string("");
	uptime = octstr_format("%ldd %ldh %ldm %lds", t/3600/24, t/3600%24, t/60%60, t%60);
	
	json_object_set_string(reply_object, "version", octstr_get_cstr(version));
	json_object_set_string(reply_object, "status", s);
	json_object_set_string(reply_object, "uptime", octstr_get_cstr(uptime));
	json_reply = json_serialize_to_string_pretty(root_value);
	
	reply = octstr_create(json_reply);
	json_free_serialized_string(json_reply);
	json_value_free(root_value);
	
	octstr_destroy(version);
	octstr_destroy(uptime);
	
	return reply;
}

Octstr *print_homepage(List *cgivars, int status_type)
{
//	static char *client_html = "templates/client.html";
//	Octstr *ret = NULL, *resource_file;
//	
//	resource_file = octstr_duplicate(resources_path);
//	octstr_append_cstr(resource_file, client_html);
//	
//	if (conn != NULL && smscconn_status(conn) != SMSCCONN_DEAD) {
//		debug("", 0, "Connection is alive");
//	}
//	
//	if (access(octstr_get_cstr(resource_file), F_OK) != -1) {
//		ret = octstr_read_file(octstr_get_cstr(resource_file));
//	} else {
//		ret = octstr_create("");
//		error(0, "Template file not found. Can't open file: %s", octstr_get_cstr(resource_file));
//	}
//	
//	octstr_destroy(resource_file);
//	
//	return ret;
}

static void smpp_client_connect(void *arg)
{
    int ret;
	int i;
    long len;
    long pending_submits;
    char *conn_error;
    double timeout;
	Octstr *cfg_filename;
	Octstr *transmit_port, *receiver_port, *transportation_type;
	Octstr *conf;
	
    Cfg *cfg;
    CfgGroup *grp;
	List *list;
	
    SMPP_PDU *pdu;
    SmppConn *smpp_conn = NULL;
    time_t last_cleanup, last_enquire_sent, last_response, now;
    Octstr *smsc_id, *host, *sys_type, *username, *password;
	
    smpp_conn = arg;
	
    smsc_id = octstr_duplicate(smpp_conn->smpp_id);
	host = octstr_duplicate(smpp_conn->smpp_host);
    sys_type = octstr_duplicate(smpp_conn->sys_type);
    username = octstr_duplicate(smpp_conn->system_id);
    password = octstr_duplicate(smpp_conn->passwd);
    transmit_port = octstr_format("%ld", smpp_conn->transmit_port);
    receiver_port = octstr_format("%ld", smpp_conn->receiver_port);
    transportation_type = octstr_format("%ld", smpp_conn->transportation_type);
	
	conf = octstr_format("group = smsc\n"
						 "smsc = smpp\n"
						 "smsc-id = %S\n"
						 "host = %S\n"
						 "port = %S\n"
						 "receive-port = %S\n"
						 "smsc-username = %S\n"
						 "smsc-password = %S\n"
						 "system-type = \"%S\"\n"
						 "transceiver-mode = %S\n\n",
						 smsc_id,
						 host,
						 transmit_port,
						 receiver_port,
						 username,
						 password,
						 sys_type,
						 transportation_type);
	
	cfg_filename = octstr_duplicate(store_location);
	octstr_append_cstr(cfg_filename, "smpp_conn.conf");
	
	octstr_write_data_to_file(conf, octstr_get_cstr(cfg_filename));
	
	cfg = cfg_create(cfg_filename);
	
	if (cfg_read(cfg) == -1)
		panic(0, "Couldn't read configuration from `%s'.", octstr_get_cstr(cfg_filename));
	
	list = cfg_get_multi_group(cfg, octstr_imm("smsc"));
	for (i = 0; i < gwlist_len(list) &&
		 (grp = gwlist_get(list, i)) != NULL; i++) {
		split_msg_counter = counter_create();
		conn = smscconn_create(grp, 1);
		if (conn == NULL)
			panic(0, "Cannot start with SMPP connection failing");
	}
}

void send_message(MsgBody *msg_vars)
{
	Msg *msg = NULL;
	Dict *dict;
	Octstr *smsc_id = NULL;
	
	msg = msg_create(sms);
	msg->sms.sms_type = mt_push;
	msg->sms.coding = 0;
	
	
	if (smscconn_id(conn)) {
		smsc_id = octstr_duplicate(smscconn_id(conn));
	} else {
		smsc_id = octstr_create("Unknown");
	}
	
	if (msg->sms.meta_data == NULL)
		msg->sms.meta_data = octstr_create("");
	
	meta_data_set_value(msg->sms.meta_data, "smpp", octstr_imm("data_coding"), msg_vars->data_coding, 1);
	
	msg->sms.msgdata = octstr_duplicate(msg_vars->message);
	msg->sms.sender = octstr_duplicate(msg_vars->sender);
	msg->sms.receiver = octstr_duplicate(msg_vars->receiver);
	msg->sms.smsc_id = octstr_duplicate(smsc_id);
	msg->sms.validity = 0;
	
	if (smpp_smscconn_status() == SMSCCONN_ACTIVE) {
		smscconn_send(conn, msg);
	}
}

static Octstr *conn_status;
static int conn_err;

void smpp_smscconn_failed(Octstr *message)
{
    conn_status = message;
    conn_ready = 1;
    conn_err = 1;
}

void smpp_smscconn_connected(Octstr *stat)
{
    conn_status = stat;
    conn_ready = 1;
    conn_err = 0;
}

int smpp_smscconn_status()
{
	return smscconn_status(conn);
}

int smpp_smscconn_stop(void)
{
	int success = 0;
	
	counter_destroy(split_msg_counter);
	if (conn != NULL && smscconn_status(conn) == SMSCCONN_DEAD) {
		info(0, "HTTP: Could not shutdown already dead smsc-id ");
	} else {
		info(0,"HTTP: Shutting down smpp connection ");
		smscconn_shutdown(conn, 1);   /* shutdown the smpp connection */
		success = 1;
	}
	
	return success;
}

Octstr *smpp_connect(SmppConn *smpp_conn)
{
    int ret;
    long len;
    long pending_submits;
    char *conn_error;
    double timeout;
    long transmit_port;
    int receiver_port, transportation_type;
    
    List *cgivars;
    SMPP_PDU *pdu;
    Connection *conn;
    Octstr *smsc_id, *host, *sys_type, *username, *password;
    
    smsc_id = octstr_duplicate(smpp_conn->smpp_id);
    host = octstr_duplicate(smpp_conn->smpp_host);
    sys_type = octstr_duplicate(smpp_conn->sys_type);
    username = octstr_duplicate(smpp_conn->system_id);
    password = octstr_duplicate(smpp_conn->passwd);
    transmit_port = smpp_conn->transmit_port;
    receiver_port = smpp_conn->receiver_port;
	transportation_type = smpp_conn->transportation_type;
	
    if (octstr_len(smsc_id) <= 0 &&
        octstr_len(host) <= 0 &&
        octstr_len(sys_type) <= 0 &&
        octstr_len(username) <= 0 &&
        octstr_len(password) <= 0) {
        
        return NULL;
    }
    conn_ready = 0;
    fd_smpp_connect = gwthread_create(smpp_client_connect, smpp_conn);
	
    return octstr_format("\"error\":\"%d\",\"status\":\"Connecting...\"", conn_err);
}

int main(int argc, char **argv)
{
	int cf_index;
	Cfg *cfg;
	
	client_status = RUNNING;
	
	gwlib_init();
	start_time = time(NULL);
	
	cf_index = get_and_set_debugs(argc, argv, NULL);
	
	if (argv[cf_index] == NULL)
		cfg_filename = octstr_create("smpp_client.conf");
	else
		cfg_filename = octstr_create(argv[cf_index]);
	cfg = cfg_create(cfg_filename);
	
	if (cfg_read(cfg) == -1)
		panic(0, "Couldn't read configuration from `%s'.", octstr_get_cstr(cfg_filename));
	
	report_versions("");
	
	if (init_client(cfg) == NULL)
		panic(0, "Initialization failed.");
	
	info(0, "----------------------------------------");
	info(0, GW_NAME " version %s starting", GW_VERSION);
	
	while (client_status != SHUTDOWN) {

		gwthread_sleep(10.0);
	}
	
	if (client_status == SHUTDOWN || client_status == DEAD)
		warning(0, "Killing signal or HTTP admin command received, shutting down...");
	
	
	client_status = DEAD;
	mutex_destroy(status_mutex);
	httpadmin_stop();
	
	alog_close();		/* if we have any */
	cfg_destroy(cfg);
	octstr_destroy(cfg_filename);
	octstr_destroy(store_location);
	gwlib_shutdown();
	
	return 0;
}
