/* audisp-cef.c --
 * Copyright (c) 2014 Mozilla Corporation.
 * Portions Copyright 2008 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Guillaume Destuynder <gdestuynder@mozilla.com>
 *   Steve Grubb <sgrubb@redhat.com>
 *
 */

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <time.h>
#include "libaudit.h"
#include "auparse.h"
#include "cef-config.h"

#define CONFIG_FILE "/etc/audisp/audisp-cef.conf"
//This is the maximum arg len for commands before truncating. Syslog often will otherwise truncate the msg.
#define MAX_ARG_LEN 1024
#define MAX_ATTR_SIZE 2047
#define BUF_SIZE 32
//Bump when the message is modified
#define CEF_AUDIT_MESSAGE_VERSION 3

extern int h_errno;

static volatile int stop = 0;
static volatile int hup = 0;
static cef_conf_t config;
static char *hostname = NULL;
static auparse_state_t *au = NULL;
static int machine = -1;
//Temporarly buffer for storing retreived fields
static char *internal_buffer;
static size_t internal_buffer_size;

typedef struct	ll {
	char val[MAX_ATTR_SIZE + 1];
	struct ll *next;
} attr_t;

struct cef_msg_type {
char	*hdr;
char	*type;
char	*app;
int	version;
const char	*msgname;
char	*msgdesc;
int	severity;
struct	ll *attr;
time_t	au_time;
unsigned int au_milli;
};

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data);

static void term_handler( int sig )
{
	stop = 1;
}

static void hup_handler( int sig )
{
	hup = 1;
}

static void reload_config(void)
{
	hup = 0;
}

/* find string distance from *in until char c is reached */
unsigned int strstok(char *in, char c)
{
	unsigned int slen, len = 0;

	if (in == NULL)
		return len;

	slen = strlen(in);

	while (in[len] != c && len <= slen)
		len++;
	len++;
	return len;
}

/* convert string to upper case */
char* strupr(char *string)
{
	char *p = string;
	while(*p) {
       	if (*p >= 'a' && *p <= 'z')
        	*p = *p - 32;

       	p++;
   	}

	return string;
}

int main(int argc, char *argv[])
{
	char tmp[MAX_AUDIT_MESSAGE_LENGTH];
	struct sigaction sa;
	struct hostent *ht;
	char nodename[64];

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = term_handler;
	sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = hup_handler;

	if (load_config(&config, CONFIG_FILE)) {
		fprintf(stderr, "FATAL: Could not read configuration file: %s", CONFIG_FILE);
		return 1;
	}

	internal_buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (internal_buffer_size < 64)
		internal_buffer_size = 16384;

	internal_buffer = (char *)alloca(internal_buffer_size);

	openlog("audisp-cef", LOG_CONS, config.facility);

	if (gethostname(nodename, 63)) {
		snprintf(nodename, 10, "localhost");
	}
	nodename[64] = '\0';
	ht = gethostbyname(nodename);
	if (ht == NULL) {
		hostname = "localhost";
		syslog(LOG_ALERT,
			"gethostbyname could not find machine hostname, please fix this. Using %s as fallback. Error: %s",
			hostname, hstrerror(h_errno));
	} else {
		hostname = ht->h_name;
	}

	au = auparse_init(AUSOURCE_FEED, 0);
	if (au == NULL) {
		syslog(LOG_ERR, "could not initialize auparse");
		free_config(&config);
		return -1;
	}

	machine = audit_detect_machine();
	if (machine < 0)
		return -1;

	auparse_add_callback(au, handle_event, NULL, NULL);

	syslog(LOG_INFO, "audisp-cef loaded\n");
	do {
		if (hup)
			reload_config();

		while (fgets_unlocked(tmp, MAX_AUDIT_MESSAGE_LENGTH, stdin) &&
							hup==0 && stop==0)
			auparse_feed(au, tmp, strnlen(tmp, MAX_AUDIT_MESSAGE_LENGTH));

		if (feof(stdin))
			break;
	} while (stop == 0);

	syslog(LOG_INFO, "audisp-cef unloaded\n");
	closelog();
	auparse_flush_feed(au);
	auparse_destroy(au);
	free_config(&config);

	return 0;
}

/*
 * This function seeks to the specified record returning its type on succees
 */
static int goto_record_type(auparse_state_t *au, int type)
{
	int cur_type;

	auparse_first_record(au);
	do {
		cur_type = auparse_get_type(au);
		if (cur_type == type) {
			auparse_first_field(au);
			return type;  // Normal exit
		}
	} while (auparse_next_record(au) > 0);

	return -1;
}

/* Removes quotes
 * Remove  CR and LF
 * @const char *in: if NULL, no processing is done.
 */
char *unescape(const char *in)
{
	if (in == NULL)
		return NULL;

	char *dst = (char *)in;
	char *s = dst;
	char *src = (char *)in;
	char c;

	while ((c = *src++) != '\0') {
		if ((c == '"') || (c == '\n') || (c == '\r') || (c == '\t')
				|| (c == '\b') || (c == '\f') || (c == '\\'))
			continue;
		*dst++ = c;
	}
	*dst++ = '\0';
	return s;
}

attr_t *cef_add_attr(attr_t *list, const char *st, const char *val)
{
	attr_t *new;

	if (val == NULL)
			return list;
	if (strstr(val, "(null)") != NULL)
			return list;

	new = malloc(sizeof(attr_t));
	snprintf(new->val, MAX_ATTR_SIZE, "%s%s ", st, unescape(val));
	new->next = list;
	return new;
}

char *get_username(int uid)
{
	char *name;
	struct passwd pwd;
	struct passwd *result;

	if (uid == -1) {
		return NULL;
	}
	if (getpwuid_r(uid, &pwd, internal_buffer, internal_buffer_size, &result) != 0) {
		return NULL;
	}
	if (result == NULL) {
		return NULL;
	}
	return pwd.pw_name;
}

char *get_proc_name(int pid)
{
	char p[1024];
	FILE *fp;
	snprintf(p, 512, "/proc/%d/status", pid);
	fp = fopen(p, "r");
	if (fp) {
		fscanf(fp, "Name: %63s", internal_buffer);
		fclose(fp);
	} else
		return NULL;
	return internal_buffer;
}

void cef_del_attrs(attr_t *head)
{
	attr_t *prev;
	while (head) {
		prev = head;
		head = head->next;
		free(prev);
	}
}

void syslog_cef_msg(struct cef_msg_type cef_msg)
{
	attr_t *head = cef_msg.attr;
	attr_t *prev;
	char msg[1500];

	snprintf(msg, 1500, "%s|%s|%s|%u|%s|%s|%u|end=%ld.%03d ", cef_msg.hdr, cef_msg.type, cef_msg.app,
		cef_msg.version, strupr(strdupa(cef_msg.msgname)), cef_msg.msgdesc, cef_msg.severity, cef_msg.au_time, cef_msg.au_milli);
	while (head) {
			snprintf(msg+strlen(msg), 1500-strlen(msg), "%s", head->val);
			prev = head;
			head = head->next;
			free(prev);
	}
	syslog(LOG_INFO, "%s", msg);
}

static void handle_event(auparse_state_t *au,
		auparse_cb_event_t cb_event_type, void *user_data)
{
	int type, rc, num=0;
	time_t au_time;

	struct cef_msg_type cef_msg = {
		.hdr		= "CEF:0",
		.type		= "Unix",
		.app		= "auditd",
		.version	= CEF_AUDIT_MESSAGE_VERSION,
		.severity	= 3,
	};

	const char *cwd = NULL, *argc = NULL, *cmd = NULL, *nametype = NULL, *saddr = NULL;
	const char *sys;
	const char *reason;
	const char *syscall = NULL;
	char fullcmd[MAX_ARG_LEN+1] = "\0";
	char fullcmdt[5] = "No\0";

	char f[8];
	int len, tmplen;
	unsigned int arg;
	int argcount, i;
	int havecef = 0;

	if (cb_event_type != AUPARSE_CB_EVENT_READY)
		return;

	while (auparse_goto_record_num(au, num) > 0) {
		type = auparse_get_type(au);
		rc = 0;
		auparse_first_field(au);
		cef_msg.au_time = auparse_get_time(au);
		cef_msg.au_milli = auparse_get_milli(au);
		switch (type) {
			case AUDIT_EXECVE:
				argc = auparse_find_field(au, "argc");
				if (argc)
					argcount = auparse_get_field_int(au);
				else
					argcount = 0;
				fullcmd[0] = '\0';
				len = 0;
				for (i = 0; i != argcount; i++) {
					goto_record_type(au, type);
					tmplen = snprintf(f, 7, "a%d", i);
					f[tmplen] = '\0';
					cmd = auparse_find_field(au, f);
					cmd = auparse_interpret_field(au);
					if (!cmd)
						continue;
					if (MAX_ARG_LEN-strlen(fullcmd) > strlen(cmd)) {
						if (len == 0)
							len += sprintf(fullcmd+len, "%s", cmd);
						else
							len += sprintf(fullcmd+len, " %s", cmd);
					} else
							strncpy(fullcmdt, "Yes\0", 4);
				}
				cef_msg.attr = cef_add_attr(cef_msg.attr, "cs2Label=Truncated cs2=", fullcmdt);
				cef_msg.attr = cef_add_attr(cef_msg.attr, "cs1Label=Command cs1=", fullcmd);
				break;
			case AUDIT_CWD:
				cwd = auparse_find_field(au, "cwd");
				if (cwd)
					cef_msg.attr = cef_add_attr(cef_msg.attr, "filePath=", cwd);

				break;
			case AUDIT_PATH:
				nametype = auparse_find_field(au, "nametype");
				if (!nametype) {
					auparse_goto_record_num(au, num);
					nametype = auparse_find_field(au, "objtype");
				}

				if (!nametype || strncmp(nametype, "PARENT", 6) == 0)
					break;

				auparse_goto_record_num(au, num);
				auparse_first_field(au);
				cef_msg.attr = cef_add_attr(cef_msg.attr, "fname=", auparse_find_field(au, "name"));
				goto_record_type(au, type);

				break;
			case AUDIT_SOCKADDR:
				saddr = auparse_find_field(au, "saddr");
				cef_msg.attr = cef_add_attr(cef_msg.attr, "dst=", auparse_interpret_sock_address(au));
				cef_msg.attr = cef_add_attr(cef_msg.attr, "dport=", auparse_interpret_sock_port(au));
				break;
			case AUDIT_SYSCALL:
				syscall = auparse_find_field(au, "syscall");
				if (!syscall) {
					cef_del_attrs(cef_msg.attr);
					return;
				}
				i = auparse_get_field_int(au);
				sys = audit_syscall_to_name(i, machine);
				if (!sys) {
					syslog(LOG_INFO, "Unknown system call %u", i);
					cef_del_attrs(cef_msg.attr);
					return;
				}

				if (!strncmp(sys, "open", 4)) {
					arg = strtoul(auparse_find_field(au, "a1"), NULL, 16);
					if (arg & O_WRONLY || arg & O_RDWR) {
						cef_msg.msgname = "WRITE";
						cef_msg.msgdesc = "Write or append to file";
					} else {
						cef_msg.msgname = "READ";
						cef_msg.msgdesc = "Read file";
					}
					cef_msg.attr = cef_add_attr(cef_msg.attr, "cs2Label=Flags cs2=", auparse_interpret_field(au));
				} else {
					cef_msg.msgname = sys;
					cef_msg.msgdesc = "Syscall called";
				}

				havecef = i;
				cef_msg.attr = cef_add_attr(cef_msg.attr, "cs3Label=AuditKey cs3=", auparse_find_field(au, "key"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "exit")) {
					reason = audit_errno_to_name(-auparse_get_field_int(au));
					if (reason)
						cef_msg.attr = cef_add_attr(cef_msg.attr, "reason=", strdupa(reason));
				}
				goto_record_type(au, type);

				cef_msg.attr = cef_add_attr(cef_msg.attr, "outcome=", strdupa(strcmp(auparse_find_field(au, "success"), "yes") == 0 ? "success" : "failure"));
				goto_record_type(au, type);

				if (auparse_find_field(au, "ppid")) {
					cef_msg.attr = cef_add_attr(cef_msg.attr, "sproc=", get_proc_name(auparse_get_field_int(au)));
					cef_msg.attr = cef_add_attr(cef_msg.attr, "spid=", auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "auid")) {
					cef_msg.attr = cef_add_attr(cef_msg.attr, "suser=", get_username(auparse_get_field_int(au)));
					cef_msg.attr = cef_add_attr(cef_msg.attr, "suid=",  auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				if (auparse_find_field(au, "uid")) {
					cef_msg.attr = cef_add_attr(cef_msg.attr, "duser=", get_username(auparse_get_field_int(au)));
					cef_msg.attr = cef_add_attr(cef_msg.attr, "duid=", auparse_get_field_str(au));
				}
				goto_record_type(au, type);

				cef_msg.attr = cef_add_attr(cef_msg.attr, "cs4Label=TTY cs4=", auparse_find_field(au, "tty"));
				goto_record_type(au, type);
				cef_msg.attr = cef_add_attr(cef_msg.attr, "dpid=", auparse_find_field(au, "pid"));
				goto_record_type(au, type);
				cef_msg.attr = cef_add_attr(cef_msg.attr, "dproc=", auparse_find_field(au, "exe"));
				goto_record_type(au, type);
				cef_msg.attr = cef_add_attr(cef_msg.attr, "cs5Label=CommandName cs5=", auparse_find_field(au, "comm"));
				goto_record_type(au, type);

				break;
			default:
				break;
		}
		num++;
	}

	if (!havecef) {
		cef_del_attrs(cef_msg.attr);
		return;
	}

	cef_msg.attr = cef_add_attr(cef_msg.attr, "dhost=", hostname);
	//This also frees cef_msg.attr
	syslog_cef_msg(cef_msg);
}
