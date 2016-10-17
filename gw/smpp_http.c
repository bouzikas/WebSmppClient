/* ====================================================================
 * The Kannel Software License, Version 1.0
 *
 * Copyright (c) 2001-2013 Kannel Group
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
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.65 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Kannel Group.  For more information on
 * the Kannel Group, please see <http://www.kannel.org/>.
 *
 * Portions of this software are based upon software originally written at
 * WapIT Ltd., Helsinki, Finland for the Kannel project.
 */

/*
 * smpp_http.c : smpp_client http adminstration commands
 *
 * NOTE: this is a special smpp_client module - it does call
 *   functions from core module! (other modules are fully
 *    encapsulated, and only called outside)
 *
 * Dimitrios Bouzikas <dimimpou@gmail.com> 6/25/15
 */

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "gwlib/gwlib.h"
#include "smpp_client.h"

#include "gwlib/json.h"

/* passed from smpp_client core */

extern volatile sig_atomic_t client_status;


extern Octstr *store_location;

/* our own thingies */

static volatile sig_atomic_t httpadmin_running;

static long	ha_port;
static Octstr *ha_interface;
static Octstr *ha_password;
static Octstr *ha_status_pw;
static Octstr *ha_allow_ip;
static Octstr *ha_deny_ip;

JSON_Object *reply_object;
JSON_Value  *root_value;

/* variables to track http calls in order to cache resource requests */
static Dict *http_calls;
static Mutex *http_calls_lock;

typedef struct Resource {
	Octstr *last_modified;
} Resource;

static Octstr *set_error_and_status(int error, const char *status)
{
    Octstr *reply;
    char *json_reply = NULL;
    
    json_object_set_number(reply_object, "error", error);
    json_object_set_string(reply_object, "status", status);
    json_reply = json_serialize_to_string_pretty(root_value);
    
    reply = octstr_create(json_reply);
    json_free_serialized_string(json_reply);
    
    return reply;
}

/*
 * check if the password matches. Return NULL if
 * it does (or is not required)
 */
static Octstr *httpd_check_authorization(List *cgivars, int status)
{
	Octstr *password;
	static double sleep = 0.01;
	
	password = http_cgi_variable(cgivars, "password");
	
	if (status) {
		if (ha_status_pw == NULL)
			return NULL;
		
		if (password == NULL)
			goto denied;
		
		if (octstr_compare(password, ha_password)!=0
			&& octstr_compare(password, ha_status_pw)!=0)
			goto denied;
	}
	else {
		if (password == NULL || octstr_compare(password, ha_password)!=0)
			goto denied;
	}
	sleep = 0.0;
	return NULL;	/* allowed */
denied:
	gwthread_sleep(sleep);
	sleep += 1.0;		/* little protection against brute force
						 * password cracking */
	return octstr_create("Denied");
}

/*
 * check if we still have time to do things
 */
static Octstr *httpd_check_status(void)
{
	if (client_status == SHUTDOWN || client_status == DEAD)
		return octstr_create("Avalanche has already started, too late to "
							 "save the sheeps");
	return NULL;
}

static Octstr *httpd_status(List *cgivars, int status_type)
{
	Octstr *reply;
	if ((reply = httpd_check_authorization(cgivars, 1))!= NULL) return reply;
	return print_status(cgivars, status_type);
}

static Octstr *httpd_homepage(List *cgivars, int status_type)
{
	Octstr *reply;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	
	return print_homepage(cgivars, status_type);
}

static Octstr *httpd_shutdown(List *cgivars, int *status_code)
{
	Octstr *reply;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	
	if (client_status == SHUTDOWN) {
		return set_error_and_status(0, "System is shuting down. Please wait...");
	}
	
	client_status = SHUTDOWN;
	status_code = HTTP_CREATED;
	
	return set_error_and_status(0, "Bringing system down, please wait....");
}

static Octstr *httpd_connect(List *cgivars, int status_type)
{
	Octstr *reply;
	Octstr *smsc_id, *host, *sys_type, *system_id, *passwd;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	
	/* check if the smsc id is given */
	smsc_id = http_cgi_variable(cgivars, "smsc_id");
	host = http_cgi_variable(cgivars, "host");
	sys_type = http_cgi_variable(cgivars, "sys_type");
	system_id = http_cgi_variable(cgivars, "username");
	passwd = http_cgi_variable(cgivars, "passwd");
	
	if (octstr_len(smsc_id) > 0
		&& octstr_len(host) > 0
		&& octstr_len(sys_type) > 0
		&& octstr_len(system_id) > 0
		&& octstr_len(passwd) > 0) {
		
		SmppConn *smpp_conn;
		smpp_conn = gw_malloc(sizeof(SmppConn));
		
		smpp_conn->smpp_id = octstr_duplicate(smsc_id);
		smpp_conn->smpp_host = octstr_duplicate(host);
		smpp_conn->sys_type = octstr_duplicate(sys_type);
		smpp_conn->system_id = octstr_duplicate(system_id);
		smpp_conn->passwd = octstr_duplicate(passwd);
		smpp_conn->transmit_port = atoi(octstr_get_cstr(http_cgi_variable(cgivars, "port")));
		smpp_conn->receiver_port = atoi(octstr_get_cstr(http_cgi_variable(cgivars, "receiver_port")));
		smpp_conn->transportation_type = atoi(octstr_get_cstr(http_cgi_variable(cgivars, "transport_type")));
		
		return smpp_connect(smpp_conn);
    } else {
        return set_error_and_status(1, "Parameters are missing");
    }
		
}

static Octstr *httpd_conn_status(List *cgivars, int status_type)
{
	Octstr *reply;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	
	if (smpp_smscconn_status() == SMSCCONN_SUCCESS) {
        return set_error_and_status(0, "Connected");
	}
    
    return set_error_and_status(0, "Connecting...");
}

static Octstr *httpd_disconnect(List *cgivars, int status_type)
{
	Octstr *reply;
	Octstr *smsc = octstr_create("SMSC");
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	if ((reply = httpd_check_status())!= NULL) return reply;
	
	/* check if the smsc id is given */
	if (smpp_smscconn_stop() == -1)
        return set_error_and_status(1, "Could not shut down smpp connection");
	else
        return set_error_and_status(0, "Smpp connection is terminated.");
}

static Octstr *http_send_message(List *cgivars, int status_type)
{
	Octstr *reply;
	Octstr *sender, *receiver, *data_coding, *message;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	if ((reply = httpd_check_status())!= NULL) return reply;
	
	/* check variables passed is given */
	sender = http_cgi_variable(cgivars, "sender");
	receiver = http_cgi_variable(cgivars, "receiver");
	data_coding = http_cgi_variable(cgivars, "data_coding");
	message = http_cgi_variable(cgivars, "message");
	
	if (octstr_len(sender)>0 && octstr_len(receiver)>0 && octstr_len(data_coding)>0 && octstr_len(message)>0) {
		MsgBody *msg_vars;
		msg_vars = gw_malloc(sizeof(MsgBody));
		
		msg_vars->sender = octstr_duplicate(sender);
		msg_vars->receiver = octstr_duplicate(receiver);
		msg_vars->data_coding = octstr_duplicate(data_coding);
		msg_vars->message = octstr_duplicate(message);
		
		send_message(msg_vars);
		
        return set_error_and_status(0, "Sending message please wait...");
	} else
		return set_error_and_status(1, "Parameters are missing");
}

static struct httpd_command {
	const char *href;
	const char *hlink;
	const char *command;
	Octstr * (*function)(List *cgivars, int status_type);
} httpd_commands[] = {
	{ "/status", "Status", "status", httpd_status },
	{ "/client", "Client", "client", httpd_homepage },
	{ "/shutdown", "Shutdown", "shutdown", httpd_shutdown },
	{ "/connect", NULL, "connect", httpd_connect },
	{ "/conn_status", NULL, "conn_status", httpd_conn_status },
	{ "/disconnect", NULL, "disconnect", httpd_disconnect },
	{ "/send_message", NULL, "send_message", http_send_message },
	{ NULL , NULL } /* terminate list */
};

static void httpd_serve(HTTPClient *client, Octstr *ourl, List *headers,
						Octstr *body, List *cgivars, Octstr *ip)
{
	Octstr *reply, *url;
	Octstr *user_agent = NULL;
	char *content_type;
	int status_type;
	int status_code = HTTP_OK;
	int i;
	long pos;
	
	reply = NULL; /* for compiler please */
	url = octstr_duplicate(ourl);
	
	/* Set default reply format according to client
	 * Accept: header */
	if (http_type_accepted(headers, "text/vnd.wap.wml")) {
		status_type = STATUS_WML;
		content_type = "text/vnd.wap.wml";
	} else if (http_type_accepted(headers, "text/html")) {
		status_type = STATUS_HTML;
		content_type = "text/html";
	} else if (http_type_accepted(headers, "text/xml")) {
		status_type = STATUS_XML;
		content_type = "text/xml";
	} else if (http_type_accepted(headers, "application/json")) {
		status_type = STATUS_JSON;
		content_type = "application/json";
    } else {
		status_type = STATUS_TEXT;
		content_type = "text/plain";
	}
	
	/* kill '/cgi-bin' prefix */
	pos = octstr_search(url, octstr_imm("/cgi-bin/"), 0);
	if (pos != -1)
		octstr_delete(url, pos, 9);
	else if (octstr_get_char(url, 0) == '/')
		octstr_delete(url, 0, 1);
	
	for (i = 0; httpd_commands[i].command != NULL; i++) {
		if (octstr_str_compare(url, httpd_commands[i].command) == 0) {
			reply = httpd_commands[i].function(cgivars, status_type);
			break;
		}
	}
	
	/* check if it is a resource file or if not exist retur `404 not found' */
	if (httpd_commands[i].command == NULL) {
		status_code = HTTP_NOT_FOUND;
		reply = octstr_format("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
							  "<html><head>\n"
							  "<title>404 Not Found</title>\n"
							  "</head><body>\n"
							  "<h1>Not Found</h1>\n"
							  "<p>The requested URL %S was not found on this server.</p>\n"
							  "</body></html>", ourl);
		
		goto finished;
	}
	
	content_type = "application/json";

finished:
	
	gw_assert(reply != NULL);
	
	http_destroy_headers(headers);
	headers = gwlist_create();
	
	http_header_add(headers, "Content-Type", content_type);
	http_send_reply(client, status_code, headers, reply);

	octstr_destroy(url);
	octstr_destroy(ourl);
	octstr_destroy(body);
	octstr_destroy(reply);
	octstr_destroy(user_agent);
	http_destroy_headers(headers);
	http_destroy_cgiargs(cgivars);
}

static void httpadmin_run(void *arg)
{
	HTTPClient *client;
	Octstr *ip, *url, *body;
	List *headers, *cgivars;
	
	while(client_status != DEAD) {
		
		client = http_accept_request(ha_port, &ip, &url, &headers, &body,
									 &cgivars);
		if (client == NULL)
			break;
		if (is_allowed_ip(ha_allow_ip, ha_deny_ip, ip) == 0) {
			info(0, "HTTP admin tried from denied host <%s>, disconnected",
				 octstr_get_cstr(ip));
			http_close_client(client);
			continue;
		}
		httpd_serve(client, url, headers, body, cgivars, ip);
		octstr_destroy(ip);
	}
	
	httpadmin_running = 0;
}


/*-------------------------------------------------------------
 * public functions
 *
 */

int httpadmin_start(Cfg *cfg)
{
	CfgGroup *grp;
	int ssl = 0;
#ifdef HAVE_LIBSSL
	Octstr *ssl_server_cert_file;
	Octstr *ssl_server_key_file;
#endif /* HAVE_LIBSSL */
	
	if (httpadmin_running) return -1;
	
	
	grp = cfg_get_single_group(cfg, octstr_imm("core"));
	if (cfg_get_integer(&ha_port, grp, octstr_imm("admin-port")) == -1)
		panic(0, "Missing admin-port variable, cannot start HTTP admin");
	
	ha_interface = cfg_get(grp, octstr_imm("admin-interface"));
	ha_password = cfg_get(grp, octstr_imm("admin-password"));
	if (ha_password == NULL)
		panic(0, "You MUST set HTTP admin-password");
	
	ha_status_pw = cfg_get(grp, octstr_imm("status-password"));
	
	ha_allow_ip = cfg_get(grp, octstr_imm("admin-allow-ip"));
	ha_deny_ip = cfg_get(grp, octstr_imm("admin-deny-ip"));
	
#ifdef HAVE_LIBSSL
	cfg_get_bool(&ssl, grp, octstr_imm("admin-port-ssl"));
	
	/*
	 * check if SSL is desired for HTTP servers and then
	 * load SSL client and SSL server public certificates
	 * and private keys
	 */
	ssl_server_cert_file = cfg_get(grp, octstr_imm("ssl-server-cert-file"));
	ssl_server_key_file = cfg_get(grp, octstr_imm("ssl-server-key-file"));
	if (ssl_server_cert_file != NULL && ssl_server_key_file != NULL) {
		/* we are fine here, the following call is now in conn_config_ssl(),
		 * so there is no reason to do this twice.
		 
		 use_global_server_certkey_file(ssl_server_cert_file,
		 ssl_server_key_file);
		 */
	} else if (ssl) {
		panic(0, "You MUST specify cert and key files within core group for SSL-enabled HTTP servers!");
	}
	
	octstr_destroy(ssl_server_cert_file);
	octstr_destroy(ssl_server_key_file);
#endif /* HAVE_LIBSSL */
	
	http_open_port_if(ha_port, ssl, ha_interface);
	
	/* Initialize those responsible for json */
    root_value = json_value_init_object();
    reply_object = json_value_get_object(root_value);
	
	if (gwthread_create(httpadmin_run, NULL) == -1)
		panic(0, "Failed to start a new thread for HTTP admin");
	
	httpadmin_running = 1;
	return 0;
}


void httpadmin_stop(void)
{	
	http_close_all_ports();
	gwthread_join_every(httpadmin_run);
	octstr_destroy(ha_interface);
	octstr_destroy(ha_password);
	octstr_destroy(ha_status_pw);
	octstr_destroy(ha_allow_ip);
	octstr_destroy(ha_deny_ip);
	
	ha_password = NULL;
	ha_status_pw = NULL;
	ha_allow_ip = NULL;
	ha_deny_ip = NULL;
    
    json_value_free(root_value);
}
