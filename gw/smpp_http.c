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

#include "gwlib/gwlib.h"
#include "smpp_client.h"

/* passed from smpp_client core */

extern volatile sig_atomic_t client_status;

/* our own thingies */

static volatile sig_atomic_t httpadmin_running;

static long	ha_port;
static Octstr *ha_interface;
static Octstr *ha_password;
static Octstr *ha_status_pw;
static Octstr *ha_allow_ip;
static Octstr *ha_deny_ip;

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

static Octstr *httpd_status(List *cgivars, int status_type)
{
	Octstr *reply;
	if ((reply = httpd_check_authorization(cgivars, 1))!= NULL) return reply;
	return print_status(cgivars, status_type);
}

static struct httpd_command {
	const char *command;
	Octstr * (*function)(List *cgivars, int status_type);
} httpd_commands[] = {
	{ "status", httpd_status },
	{ NULL , NULL } /* terminate list */
};

char *status_linebreak(int status_type)
{
	switch (status_type) {
		case STATUS_HTML:
			return "<br>\n";
		case STATUS_WML:
			return "<br/>\n";
		case STATUS_TEXT:
			return "\n";
		case STATUS_XML:
			return "\n";
		case STATUS_JSON:
			return "\n";
		default:
			return NULL;
	}
}

static void httpd_serve(HTTPClient *client, Octstr *ourl, List *headers,
						Octstr *body, List *cgivars)
{
	Octstr *reply, *final_reply, *url;
	char *content_type;
	char *header, *footer;
	int status_type;
	int i;
	long pos;
	
	reply = final_reply = NULL; /* for compiler please */
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
	} else if (http_type_accepted(headers, "text/plain")) {
		status_type = STATUS_TEXT;
		content_type = "text/plain";
	} else {
		status_type = STATUS_JSON;
		content_type = "application/json";
	}
	
	/* kill '/cgi-bin' prefix */
	pos = octstr_search(url, octstr_imm("/cgi-bin/"), 0);
	if (pos != -1)
		octstr_delete(url, pos, 9);
	else if (octstr_get_char(url, 0) == '/')
		octstr_delete(url, 0, 1);
	
	/* look for type and kill it */
	pos = octstr_search_char(url, '.', 0);
	if (pos != -1) {
		Octstr *tmp = octstr_copy(url, pos+1, octstr_len(url) - pos - 1);
		octstr_delete(url, pos, octstr_len(url) - pos);
		
		if (octstr_str_compare(tmp, "txt") == 0)
			status_type = STATUS_TEXT;
		else if (octstr_str_compare(tmp, "html") == 0)
			status_type = STATUS_HTML;
		else if (octstr_str_compare(tmp, "xml") == 0)
			status_type = STATUS_XML;
		else if (octstr_str_compare(tmp, "wml") == 0)
			status_type = STATUS_WML;
		else if (octstr_str_compare(tmp, "json") == 0)
			status_type = STATUS_JSON;
		
		octstr_destroy(tmp);
	}
	
	for (i=0; httpd_commands[i].command != NULL; i++) {
		if (octstr_str_compare(url, httpd_commands[i].command) == 0) {
			reply = httpd_commands[i].function(cgivars, status_type);
			break;
		}
	}
	
	/* check if command found */
	if (httpd_commands[i].command == NULL)
	{
		char *lb = status_linebreak(status_type);
		
		reply = octstr_format("Unknown command `%S'.%sPossible commands are:%s",
							  ourl, lb, lb);
		
		for (i=0; httpd_commands[i].command != NULL; i++)
		{
			octstr_format_append(reply, "%s%s", httpd_commands[i].command, lb);
		}
	}
	
	gw_assert(reply != NULL);
	
	if (status_type == STATUS_HTML) {
		header = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n"
		"<head><meta charset=\"utf-8\"/>"
		"<html>\n<title>" GW_NAME "</title>\n"
		"</head><body>\n<p>";
		footer = "</p>\n</body></html>\n";
		content_type = "text/html";
		
	} else if (status_type == STATUS_WML) {
		header = "<?xml version=\"1.0\"?>\n"
		"<!DOCTYPE wml PUBLIC \"-//WAPFORUM//DTD WML 1.1//EN\" "
		"\"http://www.wapforum.org/DTD/wml_1.1.xml\">\n"
		"\n<wml>\n <card>\n  <p>";
		footer = "  </p>\n </card>\n</wml>\n";
		content_type = "text/vnd.wap.wml";
	} else if (status_type == STATUS_XML) {
		header = "<?xml version=\"1.0\"?>\n"
		"<gateway>\n";
		footer = "</gateway>\n";
	} else if (status_type == STATUS_JSON) {
		header = "{";
		footer = "}";
		content_type = "application/json";
	} else {
		header = "";
		footer = "";
		content_type = "text/plain";
	}
	final_reply = octstr_create(header);
	octstr_append(final_reply, reply);
	octstr_append_cstr(final_reply, footer);
	
	http_destroy_headers(headers);
	headers = gwlist_create();
	http_header_add(headers, "Content-Type", content_type);
	
	http_send_reply(client, HTTP_OK, headers, final_reply);
	
	octstr_destroy(url);
	octstr_destroy(ourl);
	octstr_destroy(body);
	octstr_destroy(reply);
	octstr_destroy(final_reply);
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
		httpd_serve(client, url, headers, body, cgivars);
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
}
