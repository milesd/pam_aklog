/*****************************************************************************
 **  AKLOG Pluggable Authentication Module
 **  Author: Charles Clancy <mgrtcc@cs.rose-hulman.edu>
 **          Rose-Hulman Institute of Technology
 **          Department of Computer Science
 **
 **  Usage:  Place in pam.conf:
 **          other session required /lib/security/pam_aklog.so /path/to/aklog
 **          see README for more information
 **
 ****************************************************************************/

#define CONST const
#define PAM_SM_SESSION
#define PAM_SM_AUTHENTICATE

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <afs/param.h>

/* pam function for open_session on login */
extern int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, CONST char **argv) {
	char *user;		/* username of the person logging in */
	pid_t pid;		/* PID after fork */
	int status;		/* waitpid fun */

	pam_get_user(pamh, &user, NULL);		/* PAM call to get username of person logging in */

	if (setpag()==-1) return PAM_SUCCESS;	/* Create New Process Authentication Group for token */

	pid=fork();					/* procreate! */
	if (pid==0) {					/* stuff to do if we're the kid */
		setuid(getpwnam(user)->pw_uid);		/* set the UID to the person logging in, just for fun */
 		execvp(argv[0],argv);			/* exec the aklog binary specified in the PAM conf line */
	}
	waitpid(pid, &status, 0);			/* wait for child to be brutally murdered */
	if(WIFEXITED(status)) return PAM_SUCCESS;	/* if died peacefully, exit with SUCCESS */

	return PAM_SUCCESS;				/* return success anyway, because we want to */
}

/* we don't like to get rid of tokens, because you might still want them for processes
   you may be running in the background when you log off, so we're not going to unlog here */

extern int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, CONST char **argv) {
  return PAM_SUCCESS;					/* always satisfied */
}

/* This allows the use of this SESSION module as an AUTH module for services that don't support session
   based PAM, such as SCP (and I've heard rumors about IMAPd).
   Don't run run as both an auth and a session for the same service, or you'll just be wasting PAGs */

extern int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, CONST char **argv) {
  return pam_sm_open_session(pamh, flags, argc, argv);	/* call open_session -- no need to be redundant */
}

/* we're not doing any real setcred, because, of course, this isn't supposed to be an auth module
   anyway! */

extern int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, CONST char **argv) {
  return PAM_SUCCESS;					/* just return success here */
}

