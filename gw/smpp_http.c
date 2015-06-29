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
static Octstr *resources_path;

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

static Octstr *httpd_homepage(List *cgivars, int status_type)
{
	Octstr *reply;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	
	return print_homepage(cgivars, status_type);
}

static struct httpd_command {
	const char *command;
	Octstr * (*function)(List *cgivars, int status_type);
} httpd_commands[] = {
	{ "status", httpd_status },
	{ "client", httpd_homepage },
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

static char *ext_content_type(Octstr *extension)
{
    char *content_type;
    
    if (octstr_str_compare(extension, "png") == 0 || octstr_str_compare(extension, "jpg") == 0) {
        content_type = "image/png";
    } else if (octstr_str_compare(extension, "css") == 0) {
        content_type = "text/css";
    } else {
        content_type = "text/plain";
    }
    
    return content_type;
}

static Octstr *main_menu(const Octstr *active_tab)
{
	Octstr *menu, *href = NULL, *hlink = NULL;
	const char *active_class = "class=\"active\"";
	int k;
	
	menu = octstr_create("<div class=\"collapse navbar-collapse\" id=\"navbar\">"
						 "<ul class=\"nav navbar-nav\">");
	
	for (k = 1; k < 2; k++) {
		octstr_format_append(menu, "<li %s><a href=\"%s\">%s</a></li>", active_class, octstr_get_cstr(href), octstr_get_cstr(hlink));
	}
	
	octstr_append_cstr(menu, "</ul></div>");
}

static void httpd_serve(HTTPClient *client, Octstr *ourl, List *headers,
						Octstr *body, List *cgivars)
{
	Octstr *reply, *final_reply, *url;
	Octstr *res_path, *menu = NULL;
	char *content_type;
	char *header, *footer;
	int status_type;
	int status_code = HTTP_OK;
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
	
	/* check if it is a resource file, otherwise 404 not found */
	if (httpd_commands[i].command == NULL) {
		res_path = octstr_duplicate(resources_path);
		octstr_append(res_path, url);
		
		if (access(octstr_get_cstr(res_path), F_OK) != -1) {
			reply = octstr_read_file(octstr_get_cstr(res_path));
			status_type = STATUS_TEXT;
			
            long pos = octstr_search_char(res_path, '.', octstr_len(res_path) - 5);
			octstr_delete(res_path, 0, pos + 1);
            
            content_type = ext_content_type(res_path);
		}
		
		octstr_destroy(res_path);
		header = "";
		footer = "";
		
		if (reply == NULL) {
		
			status_code = HTTP_NOT_FOUND;
			reply = octstr_format("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
								   "<html><head>\n"
								   "<title>404 Not Found</title>\n"
								   "</head><body>\n"
								   "<h1>Not Found</h1>\n"
								   "<p>The requested URL %S was not found on this server.</p>\n"
								   "</body></html>", ourl);
		}
		
		goto finished;
	}
	
	if (status_type == STATUS_HTML) {
		
		Octstr *menu = main_menu(url);
		
		header = "<!DOCTYPE html>"
					"<html lang=\"en\">"
						"<head>"
							"<meta charset=\"utf-8\">"
							"<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">"
							"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
							"<!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->"
							"<title>Bootstrap 101 Template</title>"
							""
							"<!-- Bootstrap -->"
							"<link href=\"http://127.0.0.1:8000/css/bootstrap/css/bootstrap.min.css\" rel=\"stylesheet\">"
							""
							"<!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->"
							"<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->"
							"<!--[if lt IE 9]>"
							"	<script src=\"https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js\"></script>"
							"	<script src=\"https://oss.maxcdn.com/respond/1.4.2/respond.min.js\"></script>"
							"<![endif]-->"
						"</head>"
					"<body>"
					"<nav class=\"navbar navbar-default\">"
						"<div class=\"container\">"
							"<div class=\"navbar-header\">"
								"<button aria-controls=\"navbar\" aria-expanded=\"false\" data-target=\"#navbar\" data-toggle=\"collapse\" class=\"navbar-toggle collapsed\" type=\"button\">"
									"<span class=\"sr-only\">Toggle navigation</span>"
									"<span class=\"icon-bar\"></span>"
									"<span class=\"icon-bar\"></span>"
									"<span class=\"icon-bar\"></span>"
								"</button>"
								"<a href=\"#\" class=\"navbar-brand\">" GW_NAME "</a>"
							"</div>"
							"%S"		// Here we add the menu
						"</div>"
					"</nav>"
					"<div class=\"container\">"
					"";
		
		footer =		""
						"</div>"
						"<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->"
						"<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js\"></script>"
						"<!-- Include all compiled plugins (below), or include individual files as needed -->"
						"<script src=\"http://127.0.0.1:8000/css/bootstrap/js/bootstrap.min.js\"></script>"
					"</body>"
				"</html>";
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

finished:
	
	gw_assert(reply != NULL);
	final_reply = octstr_format(header, menu);
	octstr_append(final_reply, reply);
	octstr_append_cstr(final_reply, footer);
	
	http_destroy_headers(headers);
	headers = gwlist_create();
	http_header_add(headers, "Content-Type", content_type);
	http_send_reply(client, status_code, headers, final_reply);
	
	octstr_destroy(url);
	octstr_destroy(ourl);
	octstr_destroy(body);
	octstr_destroy(reply);
	octstr_destroy(menu);
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
	resources_path = cfg_get(grp, octstr_imm("store-location"));
	
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
	octstr_destroy(resources_path);
	ha_password = NULL;
	ha_status_pw = NULL;
	ha_allow_ip = NULL;
	ha_deny_ip = NULL;
}
