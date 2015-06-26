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

/* configuration filename */
Octstr *cfg_filename;

volatile sig_atomic_t client_status;

/* own global variables */

static Mutex *status_mutex;
static time_t start_time;

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
	status_mutex = mutex_create();
	
	setup_signal_handlers();
	
	httpadmin_start(cfg);
	
	return cfg;
}

Octstr *print_status(List *cgivars, int status_type)
{
	char *s, *lb;
	char *frmt, *footer;
	Octstr *ret, *str, *version;
	Octstr *password;
	time_t t;
	
	if ((lb = status_linebreak(status_type)) == NULL)
		return octstr_create("Un-supported format");
	
	t = time(NULL) - start_time;
	
	if (client_status == RUNNING)
		s = "running";
	else
		s = "shutting down";
	
	version = version_report_string("");
	
	if (status_type == STATUS_HTML) {
		frmt = "%s</p>\n\n <p>Status: %s, uptime %ldd %ldh %ldm %lds</p>\n\n";
		footer = "</p>";
	} else if (status_type == STATUS_WML) {
		frmt = "%s</p>\n\n <p>Status: %s, uptime %ldd %ldh %ldm %lds</p>\n\n";
		footer = "</p>";
	} else if (status_type == STATUS_XML) {
		frmt = "<version>%s</version>\n <status>%s, uptime %ldd %ldh %ldm %lds</status>\n";
		footer = "</p>";
	} else if (status_type == STATUS_JSON) {
		octstr_url_encode(version);
		frmt = "\"version\":\"%s\",\"status\":\"%s\",\"uptime\":\"%ldd %ldh %ldm %lds\"";
		footer = "";
	} else {
		frmt = "%s</p>\n\n <p>Status: %s, uptime %ldd %ldh %ldm %lds</p>\n\n";
		footer = "";
	}
	
	ret = octstr_format(frmt, octstr_get_cstr(version), s, t/3600/24, t/3600%24, t/60%60, t%60);
	
	octstr_append_cstr(ret, footer);
	octstr_destroy(version);
	
	return ret;
}

Octstr *print_homepage(List *cgivars, int status_type)
{
	Octstr *ret;
	
	
	
	return ret;
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
	
	alog_close();		/* if we have any */
	cfg_destroy(cfg);
	octstr_destroy(cfg_filename);
	gwlib_shutdown();
	
	return 0;
}
