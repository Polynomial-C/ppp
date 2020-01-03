
/*
 *  Author: Arvin Schnell <arvin@suse.de>
 *
 *  This plugin let's you pass the password to the pppd via
 *  a file descriptor. That's easy and secure - no fiddling
 *  with pap- and chap-secrets files.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "pppd.h"

char pppd_version[] = VERSION;

static char save_passwd[MAXSECRETLEN];

static int readpassword __P((char **));
static option_t options[] = {
    { "passwordfd", o_special, (void *)readpassword,
      "Receive password on this file descriptor" },
    { NULL }
};

static int pwfd_check (void)
{
    return 1;
}

static int readpassword(char **argv)
{
    char *arg = *argv;
    int passwdfd = -1;
    int chunk, len;

    if (sscanf(arg, "%d", &passwdfd) != 1 || passwdfd < 0)
    {
	error ("\"%s\" is not a valid file descriptor number", arg);
	return 0;
    }

    len = 0;
    do {
	chunk = read (passwdfd, save_passwd + len, MAXSECRETLEN - 1 - len);
	if (chunk == 0)
	    break;
	if (chunk < 0) {
	    error ("Can't read secret from fd %d", passwdfd);
	    return 0;
	}
	len += chunk;
    } while (len < MAXSECRETLEN - 1);
    save_passwd[len] = 0;
    close (passwdfd);

    return 1;
}

static int pwfd_passwd (char *user, char *passwd)
{
    if (passwd != NULL)
	strcpy (passwd, save_passwd);
    return 1;
}

void plugin_init (void)
{
    add_options (options);

    pap_check_hook = pwfd_check;
    pap_passwd_hook = pwfd_passwd;

    chap_check_hook = pwfd_check;
    chap_passwd_hook = pwfd_passwd;
}
