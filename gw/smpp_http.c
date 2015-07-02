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

#include <sys/stat.h>
#include <sys/types.h>

#include "gwlib/gwlib.h"
#include "smpp_client.h"

/* passed from smpp_client core */

extern volatile sig_atomic_t client_status;


extern Octstr *resources_path;

/* our own thingies */

static volatile sig_atomic_t httpadmin_running;

static long	ha_port;
static Octstr *ha_interface;
static Octstr *ha_password;
static Octstr *ha_status_pw;
static Octstr *ha_allow_ip;
static Octstr *ha_deny_ip;

/* variables to track http calls in order to cache resource requests */
static Dict *http_calls;
static Mutex *http_calls_lock;

typedef struct Resource {
	Octstr *last_modified;
} Resource;

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

static Octstr *httpd_shutdown(List *cgivars, int status_type)
{
	Octstr *reply;
	
	if ((reply = httpd_check_authorization(cgivars, 0))!= NULL) return reply;
	
	if (client_status == SHUTDOWN) {
		return octstr_create("System is shuting down. Please wait...");
	}
	
	client_status = SHUTDOWN;
	
	return octstr_create("Bringing system down....");
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
	int i;

	menu = octstr_create(""
		"<nav class=\"navbar navbar-default\">"
			"<div class=\"container\">"
				"<div class=\"navbar-header\">"
					"<button aria-controls=\"navbar\" aria-expanded=\"false\" data-target=\"#navbar\" "
						"data-toggle=\"collapse\" class=\"navbar-toggle collapsed\" type=\"button\">"
						"<span class=\"sr-only\">Toggle navigation</span>"
						"<span class=\"icon-bar\"></span>"
						"<span class=\"icon-bar\"></span>"
						"<span class=\"icon-bar\"></span>"
					"</button>"
					"<a href=\"#\" class=\"navbar-brand\">" GW_NAME "</a>"
				"</div>"
				"<div class=\"collapse navbar-collapse\" id=\"navbar\">"
					"<ul class=\"nav navbar-nav\">");
	
	for (i = 0; httpd_commands[i].href != NULL; i++) {
		if (octstr_str_compare(active_tab, httpd_commands[i].command) == 0) {
			octstr_format_append(menu, "<li %s>", active_class);
		} else {
			octstr_append_cstr(menu, "<li>");
		}
		octstr_format_append(menu, "<a href=\"%s\">%s</a></li>", httpd_commands[i].href, httpd_commands[i].hlink);
	}
	
	octstr_append_cstr(menu,
					"</ul>"
				"</div>"
			"</div>"
		"</nav>");
	
	return menu;
}

static Octstr *file_last_modified(char *filepath)
{
	struct stat attrib;
	char date[40];
	struct tm tm;
	Octstr *date_modified = NULL;
	
	stat(filepath, &attrib);
	tm = gw_localtime(attrib.st_ctime);
	
	gw_strftime(date, 40, "%a, %d %b %Y %H:%M:%S %Z", &tm);
	
	date_modified = octstr_create(date);
	date[0] = 0;
	
	return date_modified;
}

static void http_calls_destroy(void)
{
	dict_destroy(http_calls);
	mutex_destroy(http_calls_lock);
}

static void http_calls_res_destroy(void *item)
{
	Resource *res = (void *)item;
	
	if (res == NULL) {
		return;
	}
	
	if (res->last_modified) {
		octstr_destroy(res->last_modified);
	}
	
	res->last_modified = NULL;
	
	gw_free(res);
}

static void http_calls_init(void)
{
	http_calls = dict_create(1024, http_calls_res_destroy);
	http_calls_lock = mutex_create();
}

static inline Octstr *http_call_key(Octstr *ip, Octstr *file, Octstr *user_agent)
{
	return octstr_format("%S:%S:%S", ip, file, user_agent);
}

static Resource *http_calls_get(Octstr *ip, Octstr *file, Octstr *user_agent)
{
	Octstr *key;
	List *list = NULL;
	Resource *res = NULL;
	
	key = http_call_key(ip, file, user_agent);
	mutex_lock(http_calls_lock);
	res = dict_get(http_calls, key);
	mutex_unlock(http_calls_lock);
	
	return res;
}

static void http_calls_put(Octstr *ip, Octstr *file, Resource *resource, Octstr *user_agent)
{
	Octstr *key;
	List *list;
	Resource *res;
	
	key = http_call_key(ip, file, user_agent);
	mutex_lock(http_calls_lock);
	res = dict_get(http_calls, key);
	if (res == NULL) {
		dict_put(http_calls, key, resource);
	}
	mutex_unlock(http_calls_lock);
}


static void httpd_serve(HTTPClient *client, Octstr *ourl, List *headers,
						Octstr *body, List *cgivars, Octstr *ip)
{
	Octstr *reply, *final_reply, *url;
	Octstr *res_path, *menu = NULL, *last_modified = NULL;
	Octstr *user_agent = NULL;
	char *content_type;
	char *header, *container, *footer;
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
	
	/* check if it is a resource file or if not exist retur `404 not found' */
	if (httpd_commands[i].command == NULL) {
		res_path = octstr_duplicate(resources_path);
		octstr_append(res_path, url);
		
		if (access(octstr_get_cstr(res_path), F_OK) != -1) {
			reply = octstr_read_file(octstr_get_cstr(res_path));
			status_type = STATUS_TEXT;
			
			Resource *res = NULL;
			
			user_agent = http_header_value(headers, octstr_imm("User-Agent"));
			res = http_calls_get(ip, res_path, user_agent);
			
			last_modified = file_last_modified(octstr_get_cstr(res_path));
			if (res != NULL) {
				if (octstr_compare(res->last_modified, last_modified) == 0) {
					status_code = HTTP_NOT_MODIFIED;
				} else {
					res->last_modified = octstr_duplicate(last_modified);
				}
			} else {
				res = gw_malloc(sizeof(*res));
				res->last_modified = octstr_duplicate(last_modified);
				http_calls_put(ip, res_path, res, user_agent);
			}
			
            long pos = octstr_search_char(res_path, '.', octstr_len(res_path) - 5);
			octstr_delete(res_path, 0, pos + 1);
			
            content_type = ext_content_type(res_path);
		}
		
		octstr_destroy(res_path);
		
		header = "";
		container = "";
		footer = "";
		menu = octstr_create("");
		
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
		
		menu = main_menu(url);
		
		header = "<!DOCTYPE html>"
					"<html lang=\"en\">"
						"<head>"
							"<meta charset=\"utf-8\">"
							"<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">"
							"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
							"<!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->"
							"<title>" GW_NAME " v." GW_VERSION " </title>"
							""
							"<!-- Bootstrap -->"
							"<link href=\"http://127.0.0.1:8000/css/bootstrap/css/bootstrap.min.css\" rel=\"stylesheet\">"
							"<link href=\"http://127.0.0.1:8000/css/bootstrap/css/bootstrap-theme.min.css\" rel=\"stylesheet\">"
							"<link href=\"http://127.0.0.1:8000/css/style.css\" rel=\"stylesheet\">"
							""
							"<!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->"
							"<!-- WARNING: Respond.js doesn't work if you view the page via file:// -->"
							"<!--[if lt IE 9]>"
							"	<script src=\"https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js\"></script>"
							"	<script src=\"https://oss.maxcdn.com/respond/1.4.2/respond.min.js\"></script>"
							"<![endif]-->"
						"</head>"
						"<body>";
	
		container =	"<div class=\"container\">";
		
		footer = "</div>"
					"<footer class=\"footer\">"
						"<div class=\"container\">"
							"<p>" GW_NAME " v." GW_VERSION " | Copyright 2015 &copy Dimitris Bouzikas</p>"
						"</div>"
					"</footer>"
					"<!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->"
					"<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js\"></script>"
					"<!-- Include all compiled plugins (below), or include individual files as needed -->"
					"<script src=\"http://127.0.0.1:8000/css/bootstrap/js/bootstrap.min.js\"></script>"
				"</body>"
			"</html>";
		
		content_type = "text/html";
	} else if (status_type == STATUS_JSON) {
		header = "{";
		container = "";
		footer = "}";
		content_type = "application/json";
	} else {
		header = "";
		container = "";
		footer = "";
		content_type = "text/plain";
	}

finished:
	
	gw_assert(reply != NULL);
	final_reply = octstr_format("%s%s", header, octstr_get_cstr(menu));
	octstr_append_cstr(final_reply, container);
	octstr_append(final_reply, reply);
	octstr_append_cstr(final_reply, footer);
	
	http_destroy_headers(headers);
	headers = gwlist_create();
	
	if (last_modified != NULL) {
		http_header_add(headers, "Last-Modified", octstr_get_cstr(last_modified));
	}
	
	http_header_add(headers, "Content-Type", content_type);
	http_send_reply(client, status_code, headers, final_reply);

	octstr_destroy(url);
	octstr_destroy(ourl);
	octstr_destroy(body);
	octstr_destroy(reply);
	octstr_destroy(menu);
	octstr_destroy(last_modified);
	octstr_destroy(final_reply);
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
	
	http_calls_init();
	
	if (gwthread_create(httpadmin_run, NULL) == -1)
		panic(0, "Failed to start a new thread for HTTP admin");
	
	httpadmin_running = 1;
	return 0;
}


void httpadmin_stop(void)
{
	http_calls_destroy();
	
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
