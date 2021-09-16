/*
 * Copyright (c) 2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>

#include <vyatta-cfg/client/mgmt.h>

#define	VERIFY_PASSWORD	1
#define CHANGE_PASSWORD	2

static int password(pam_handle_t *pamh, struct passwd *pw,
		    const char *cur_pw, const char *new_pw,
		    unsigned int flag)
{
	struct configd_conn *conn = NULL;
	struct configd_error err;
	const char ns[] = "vyatta-system-login-v1";
	char name[32];
	char input[4096];

	memset(&err, 0, sizeof(err));

	if (setregid(pw->pw_gid, -1) == -1) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - setregid() error: %s",
			   strerror(errno));
		goto error;
	}
	if (setreuid(pw->pw_uid, -1) == -1) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - setreuid() error: %s",
			   strerror(errno));
		goto error;
	}

	conn = (struct configd_conn *)calloc(1, sizeof(struct configd_conn));
	if (conn == NULL) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - configd_conn allocation failed");
		goto error;
	}
	if (configd_open_connection(conn) < 0) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - configd_open_connection() error: %s",
			   strerror(errno));
		goto error;
	}

	if (flag == VERIFY_PASSWORD) {
		strncpy(name, "verify-password", sizeof(name));
		snprintf(input, sizeof(input),
			 "{\"current-password\":\"%s\"}", cur_pw);
	} else if (flag == CHANGE_PASSWORD) {
		strncpy(name, "change-password", sizeof(name));
		snprintf(input, sizeof(input),
			 "{\"current-password\":\"%s\",\"new-password\":\"%s\"}",
			 cur_pw, new_pw);
	}
	if (configd_call_rpc(conn, ns, name, input, &err) == NULL) {
		pam_syslog(pamh, LOG_DEBUG,
			   "password - configd_call_rpc() error: %s",
			   strerror(errno));
		if (err.text && write(STDERR_FILENO, err.text,
				      strlen(err.text)) == -1) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password - write() error: %s",
				   strerror(errno));
		}
		goto error;
	}
	return 0;
error:
	if (err.text)
		configd_error_free(&err);
	if (conn) {
		configd_close_connection(conn);
		free(conn);
	}
	return -1;
}

static int user_password(pam_handle_t *pamh, const char *user,
			 struct passwd *pw, const char *cur_pw,
			 const char *new_pw, unsigned int flag)
{
	pid_t pid;

	pid = fork();
	if (pid == -1) {
		pam_syslog (pamh, LOG_DEBUG, "password - fork() error: %s",
			    strerror(errno));
		return PAM_SYSTEM_ERR;
	}
	if (pid > 0) {
		int status = 0;
		pid_t rc;

		while ((rc = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
			;
		if (rc == (pid_t)-1) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password - waitpid() error: %s",
				   strerror(errno));
			return PAM_SYSTEM_ERR;
		} else if (status != 0) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password change failed for user %s",
				   user);
			return PAM_AUTHTOK_ERR;
		}
		return PAM_SUCCESS;
	} else {
		if (password(pamh, pw, cur_pw, new_pw, flag) != 0) {
			pam_syslog(pamh, LOG_DEBUG,
				   "password change failed for user %s",
				   user);
			_exit(1);
		}
		_exit(0);
	}
	return PAM_SYSTEM_ERR;
}

int
pam_sm_chauthtok(pam_handle_t *pamh, int pam_flags,
                    int argc __attribute__ ((unused)),
                    const char **argv __attribute__ ((unused)))
{
	const char *user;
	const void *newpw, *oldpw;
	struct passwd *pw;
	const char *new_pw, *cur_pw;
	char *resp[2] = {NULL, NULL};
	int ret;

	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_DEBUG, "password - user %s is unknown",
			   user);
		return ret;
	}
	pw = pam_modutil_getpwnam(pamh, user);
	if (pw == NULL) {
		pam_syslog(pamh, LOG_ERR,
			   "password - no passwd entry for user %s", user);
		return PAM_USER_UNKNOWN;
	}
	if (pam_flags & PAM_PRELIM_CHECK) {
		if (pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &resp[0],
				"%s", "Current password: ") != PAM_SUCCESS
				|| resp[0] == NULL) {
			pam_syslog (pamh, LOG_DEBUG,
				    "password - pam_prompt() error: %s",
				    strerror(errno));
			return PAM_AUTHTOK_ERR;
		}
		pam_set_item(pamh, PAM_OLDAUTHTOK, resp[0]);
		return user_password(pamh, user, pw, resp[0], NULL,
				     VERIFY_PASSWORD);
	} else if ((pam_flags & PAM_UPDATE_AUTHTOK) &&
	     pam_get_item(pamh, PAM_AUTHTOK, &newpw) != PAM_SUCCESS) {
		return PAM_SUCCESS;
	}
	pam_set_item(pamh, PAM_AUTHTOK, newpw);
	new_pw = (const char *)newpw;
	if (pam_get_item(pamh, PAM_OLDAUTHTOK, &oldpw) != PAM_SUCCESS) {
		pam_syslog (pamh, LOG_DEBUG,
			    "password - pam_get_item() on OLDAUTHTOK error: %s",
			    strerror(errno));
		return PAM_AUTHTOK_ERR;
	}
	cur_pw = (const char *)oldpw;
	return user_password(pamh, user, pw, cur_pw, new_pw,
			     CHANGE_PASSWORD);
}
