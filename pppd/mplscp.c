
/* MPLSCP - Serge.Krier@advalvas.be (C) 2001 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pppd.h"
#include "fsm.h"
#include "mplscp.h"


/* local vars */
/* static int mplscp_is_up; */                  /* have called np_up() */

/*
 * Callbacks for fsm code.  (CI = Configuration Information)
 */
static void mplscp_resetci (fsm *);	/* Reset our CI */
static int  mplscp_cilen (fsm *);	/* Return length of our CI */
static void mplscp_addci (fsm *, u_char *, int *); 	/* Add our CI */
static int  mplscp_ackci (fsm *, u_char *, int);	/* Peer ack'd our CI */
static int  mplscp_nakci (fsm *, u_char *, int);	/* Peer nak'd our CI */
static int  mplscp_rejci (fsm *, u_char *, int);	/* Peer rej'd our CI */
static int  mplscp_reqci (fsm *, u_char *, int *, int); /* Rcv CI */
static void mplscp_up (fsm *);		/* We're UP */
static void mplscp_down (fsm *);	/* We're DOWN */
static void mplscp_finished (fsm *);	/* Don't need lower layer */

fsm mplscp_fsm[NUM_PPP];		/* MPLSCP fsm structure */

static fsm_callbacks mplscp_callbacks = { /* MPLSCP callback routines */
  mplscp_resetci,		/* Reset our Configuration Information */
  mplscp_cilen,			/* Length of our Configuration Information */
  mplscp_addci,			/* Add our Configuration Information */
  mplscp_ackci,			/* ACK our Configuration Information */
  mplscp_nakci,			/* NAK our Configuration Information */
  mplscp_rejci,			/* Reject our Configuration Information */
  mplscp_reqci,			/* Request peer's Configuration Information */
  mplscp_up,			/* Called when fsm reaches OPENED state */
  mplscp_down,			/* Called when fsm leaves OPENED state */
  NULL,			        /* Called when we want the lower layer up */
  mplscp_finished,		/* Called when we want the lower layer down */
  NULL,			        /* Called when Protocol-Reject received */
  NULL,			        /* Retransmission is necessary */
  NULL,			        /* Called to handle protocol-specific codes */
  "MPLSCP"			/* String name of protocol */
};

static option_t mplscp_option_list[] = {
    { "mpls", o_bool, &mplscp_protent.enabled_flag,
      "Enable MPLSCP (and MPLS)", 1 },
    { NULL } };

/*
 * Protocol entry points from main code.
 */

static void mplscp_init (int);
static void mplscp_open (int);
static void mplscp_close (int, char *);
static void mplscp_lowerup (int);
static void mplscp_lowerdown (int);
static void mplscp_input (int, u_char *, int);
static void mplscp_protrej (int);
static int  mplscp_printpkt (u_char *, int,
				 void (*) (void *, char *, ...), void *);

struct protent mplscp_protent = {
    PPP_MPLSCP,
    mplscp_init,
    mplscp_input,
    mplscp_protrej,
    mplscp_lowerup,
    mplscp_lowerdown,
    mplscp_open,
    mplscp_close,
    mplscp_printpkt,
    NULL,
    0,                            /* MPLS not enabled by default */
    "MPLSCP",
    "MPLS",
    mplscp_option_list,
    NULL,
    NULL,
    NULL
};

/*
 * mplscp_init - Initialize MPLSCP.
 */
static void
mplscp_init(int unit) {

  fsm *f = &mplscp_fsm[unit];
  
  f->unit = unit;
  f->protocol = PPP_MPLSCP;
  f->callbacks = &mplscp_callbacks;  
  fsm_init(&mplscp_fsm[unit]); 
  
}

/*
 * mplscp_open - MPLSCP is allowed to come up.
 */
static void
mplscp_open(int unit) {
  
  fsm_open(&mplscp_fsm[unit]);

}

/*
 * mplscp_close - Take MPLSCP down.
 */
static void
mplscp_close(int unit, char *reason) {

  fsm_close(&mplscp_fsm[unit], reason);

}

/*
 * mplscp_lowerup - The lower layer is up.
 */
static void
mplscp_lowerup(int unit) {

  fsm_lowerup(&mplscp_fsm[unit]);
}

/*
 * mplscp_lowerdown - The lower layer is down.
 */
static void
mplscp_lowerdown(int unit) {
  
  fsm_lowerdown(&mplscp_fsm[unit]);
}

/*
 * mplscp_input - Input MPLSCP packet.
 */
static void
mplscp_input(int unit, u_char *p, int len) {

  fsm_input(&mplscp_fsm[unit], p, len);
}

/*
 * mplscp_protrej - A Protocol-Reject was received for MPLSCP.
 * Pretend the lower layer went down, so we shut up.
 */
static void
mplscp_protrej(int unit) {

    fsm_lowerdown(&mplscp_fsm[unit]);
}

/*
 * mplscp_resetci - Reset our CI.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static void
mplscp_resetci(fsm *f) {

  return;
}

/*
 * mplscp_cilen - Return length of our CI.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static int
mplscp_cilen(fsm *f) {

  return 0;
}

/*
 * mplscp_addci - Add our desired CIs to a packet.
 * Called by fsm_sconfreq, Send Configure Request.
 */
static void
mplscp_addci(fsm *f, u_char *ucp, int *lenp) {

}

/*
 * ipcp_ackci - Ack our CIs.
 * Called by fsm_rconfack, Receive Configure ACK.
 *
 * Returns:
 *	0 - Ack was bad.
 *	1 - Ack was good.
 */
static int
mplscp_ackci(fsm *f, u_char *p, int  len) {
  
  return 1;

}

/*
 * mplscp_nakci - Peer has sent a NAK for some of our CIs.
 * This should not modify any state if the Nak is bad
 * or if MPLSCP is in the OPENED state.
 * Calback from fsm_rconfnakrej - Receive Configure-Nak or Configure-Reject.
 *
 * Returns:
 *	0 - Nak was bad.
 *	1 - Nak was good.
 */
static int
mplscp_nakci(fsm *f, u_char *p, int len) {

  return 1;
}

/*
 * MPLSVP_rejci - Reject some of our CIs.
 * Callback from fsm_rconfnakrej.
 */
static int
mplscp_rejci(fsm *f, u_char *p, int len) {

  return 1;

}

/*
 * mplscp_reqci - Check the peer's requested CIs and send appropriate response.
 * Callback from fsm_rconfreq, Receive Configure Request
 *
 * Returns: CONFACK, CONFNAK or CONFREJ and input packet modified
 * appropriately.  If reject_if_disagree is non-zero, doesn't return
 * CONFNAK; returns CONFREJ if it can't return CONFACK.
 */
static int
mplscp_reqci(fsm *f, u_char *inp, int *len, int reject_if_disagree) {
  
  
  int rc = CONFACK;		/* Final packet return code */
   
  PUTCHAR(CONFACK,inp);

  return rc;

}

static void
mplscp_up(fsm *f) {

  sifnpmode(f->unit, PPP_MPLS_UC, NPMODE_PASS);
  /*  sifnpmode(f->unit, PPP_MPLS_MC, NPMODE_PASS);*/
  
  np_up(f->unit, PPP_MPLS_UC);
  /*  np_up(f->unit, PPP_MPLS_MC);*/
  /*  ipcp_is_up = 1;*/

  
#if 1
  printf("MPLSCP is OPENED\n");
#endif

}

static void
mplscp_down(fsm *f) {
  
  sifnpmode(f->unit, PPP_MPLS_UC, NPMODE_DROP);
  /*  sifnpmode(f->unit, PPP_MPLS_MC, NPMODE_DROP);*/

  sifdown(f->unit); 
  
#if 1
  printf("MPLSCP is CLOSED\n");
#endif
  

}

static void 
mplscp_finished(fsm *f) {
  
  np_finished(f->unit, PPP_MPLS_UC);
  /*  np_finished(f->unit, PPP_MPLS_MC);*/

}

/*
 * mpls_printpkt - print the contents of an MPLSCP packet.
 */
static char *mplscp_codenames[] = {
    "ConfReq", "ConfAck", "ConfNak", "ConfRej",
    "TermReq", "TermAck", "CodeRej"
};

static int
mplscp_printpkt(u_char *p, int plen, 
		void (*printer) (void *, char *, ...),
		void *arg) {
 
    int code, id, len, olen;
    u_char *pstart, *optend;

    if (plen < HEADERLEN)
	return 0;
    pstart = p;
    GETCHAR(code, p);
    GETCHAR(id, p);
    GETSHORT(len, p);
    if (len < HEADERLEN || len > plen)
	return 0;

    if (code >= 1 && code <= sizeof(mplscp_codenames) / sizeof(char *))
	printer(arg, " %s", mplscp_codenames[code-1]);
    else
	printer(arg, " code=0x%x", code);
    printer(arg, " id=0x%x", id);
    len -= HEADERLEN;
    switch (code) {
    case CONFREQ:
    case CONFACK:
    case CONFNAK:
    case CONFREJ:
	/* print option list */
	while (len >= 2) {
	    GETCHAR(code, p);
	    GETCHAR(olen, p);
	    p -= 2;
	    if (olen < 2 || olen > len) {
		break;
	    }
	    printer(arg, " <");
	    len -= olen;
	    optend = p + olen;
	    while (p < optend) {
		GETCHAR(code, p);
		printer(arg, " %.2x", code);
	    }
	    printer(arg, ">");
	}
	break;

    case TERMACK:
    case TERMREQ:
	if (len > 0 && *p >= ' ' && *p < 0x7f) {
	    printer(arg, " ");
	    print_string((char *)p, len, printer, arg);
	    p += len;
	    len = 0;
	}
	break;
    }

    /* print the rest of the bytes in the packet */
    for (; len > 0; --len) {
	GETCHAR(code, p);
	printer(arg, " %.2x", code);
    }

    return p - pstart;

}
