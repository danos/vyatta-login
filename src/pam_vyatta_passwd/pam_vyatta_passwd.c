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


char *pwdfile = "/opt/vyatta/sbin/vyatta-update-password";
char *lu = "/opt/vyatta/sbin/lu";
char *pwduser = "vyattapwdcfg";

int
pam_sm_chauthtok(pam_handle_t *pamh, int pam_flags,
                    int argc __attribute__ ((unused)),
                    const char **argv __attribute__ ((unused)))
{
	const char *user;
	const void *newpwd;
	struct passwd *pwd, *pwdcfg;
	struct stat buf;
	pid_t pid;
	int fd[2];
	int ret;

	if (stat(pwdfile, &buf) == -1) {
		pam_syslog(pamh, LOG_DEBUG, "password - stat() error: %s",
				strerror(errno));
		return PAM_ABORT;
	}
	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_DEBUG,
				"password - user %s is unknown",
				user);
		return ret;
	}
	pwd = pam_modutil_getpwnam(pamh, user);
	if (pwd == NULL) {
		pam_syslog(pamh, LOG_ERR,
				"password - no passwd entry for user %s",
				user);
		return PAM_USER_UNKNOWN;
	}
	pwdcfg = pam_modutil_getpwnam(pamh, "vyattapwdcfg");
	if (pwdcfg == NULL) {
		pam_syslog(pamh, LOG_ERR,
			"password - no passwd entry for user 'vyattapwdcfg'");
		return PAM_USER_UNKNOWN;
	}
	if (!((pam_flags & PAM_UPDATE_AUTHTOK) &&
	     pam_get_item(pamh, PAM_AUTHTOK, &newpwd) == PAM_SUCCESS))
		return PAM_SUCCESS;
	pam_set_item(pamh, PAM_AUTHTOK, newpwd);

	if (pipe(fd)) {
		pam_syslog (pamh, LOG_DEBUG, "password - pipe() error: %s",
				strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	pid = fork();
	if (pid == -1) {
		pam_syslog (pamh, LOG_DEBUG, "password - fork() error: %s",
				strerror(errno));
		return PAM_SYSTEM_ERR;
	}
	if (pid > 0) {
		int status = 0;
		pid_t rc;
		char *buf;

		if (asprintf(&buf, "%s:%s", user, (const char *)newpwd) == 1) {
			pam_syslog(pamh, LOG_DEBUG,
					"password - asprintf() error: %s",
					strerror(errno));
			return PAM_SYSTEM_ERR;
		}
		if (write(fd[1], buf, strlen(buf)) == -1) {
			pam_syslog(pamh, LOG_DEBUG,
					"password - write() error: %s",
					strerror(errno));
			free(buf);
			return PAM_SYSTEM_ERR;
		}
		free(buf);
		close(fd[0]);
		close(fd[1]);

		while ((rc = waitpid(pid, &status, 0)) == -1 && errno == EINTR)
			;
		if (rc == (pid_t)-1) {
			pam_syslog(pamh, LOG_DEBUG,
					"password - waitpid() error: %s",
					strerror(errno));
			return PAM_SYSTEM_ERR;
		} else if (status != 0) {
			pam_syslog(pamh, LOG_DEBUG,
					"password renewal failed for user %s",
					user);
			return PAM_AUTHTOK_ERR;
		}
		return PAM_SUCCESS;
	} else {
		char *args[] = { lu, "-user", (char *)pwduser, pwdfile, NULL };
		char *env[] = { NULL };;

		if (dup2(fd[0], STDIN_FILENO) == -1) {
			pam_syslog(pamh, LOG_DEBUG,
					"password - dup2() error: %s",
					strerror(errno));
			_exit(1);;
		}
		close(fd[1]);

		if (setregid(pwdcfg->pw_gid, -1) == -1) {
			pam_syslog(pamh, LOG_DEBUG,
					"password - setregid() error: %s",
					strerror(errno));
			_exit(1);;
		}
		if (setreuid(pwdcfg->pw_uid, -1) == -1) {
			pam_syslog(pamh, LOG_DEBUG,
					"password - setreuid() error: %s",
					strerror(errno));
			_exit(1);;
		}
		execve (args[0], args, env);

		pam_syslog (pamh, LOG_DEBUG,
				"password renewal failed for user %s",
				user);
		_exit(1);
	}
	return PAM_SYSTEM_ERR;
}
