/*-
 * Copyright (c) 2014 Antti Kantee <pooka@fixup.fi>
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * A simple tool for interfacing with rump-pktgenif and measuring performance.
 *
 * Status: works && in the works ...
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "pktgenif.h"

#define RUMP_SERVURL "unix:///tmp/pktgen"
#define PKTCNT 100000000
#define PKTSIZE 22

static void
myexit(void)
{

	rump_sys_reboot(0, 0);
}

static sig_atomic_t ehit;
static void
hand(int sig)
{

	ehit = 1;
}

static uint64_t
sendpackets(uint64_t pktcnt, size_t dlen)
{
	struct sockaddr_in sin; /* XXX: compat enough */
	void *sendpayload;
	uint64_t sent;
	int s;

	sendpayload = malloc(dlen);
	s = rump_sys_socket(RUMP_PF_INET, RUMP_SOCK_DGRAM, 0);
	if (s == -1)
		return 0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = RUMP_AF_INET;
	sin.sin_port = htons(55443);
	sin.sin_addr.s_addr = inet_addr("1.2.3.1");

	for (sent = 0; sent < pktcnt && !ehit; sent++) {
		if (rump_sys_sendto(s, sendpayload, dlen, 0,
		    (struct sockaddr *)&sin, sizeof(sin)) < dlen)
			break; 
	}
	return sent;
}

#define PKT_MAXLEN (1<<16)
static uint64_t
receivepackets(uint64_t pktcnt)
{
	void *mem = malloc(PKT_MAXLEN);
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	uint64_t rcvd;
	int s;

	s = rump_sys_socket(RUMP_PF_INET, RUMP_SOCK_DGRAM, 0);
	if (s == -1)
		return 0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = RUMP_AF_INET;
	sin.sin_port = htons(54321);
	sin.sin_addr.s_addr = INADDR_ANY;
	if (rump_sys_bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		return 0;

	for (rcvd = 0; rcvd < pktcnt && !ehit; rcvd++) {
		if (rump_sys_recvfrom(s, mem, PKT_MAXLEN, 0,
		    (struct sockaddr *)&sin, &slen) == -1)
			break;
	}
	return rcvd;
}

static void
usage(void)
{

	fprintf(stderr, "nope\n");
	exit(1);
}

#define ACTION_SEND 0x01
#define ACTION_RECV 0x02

int
main(int argc, char *argv[])
{
	struct timeval tv_s, tv_e, tv;
	uint64_t ifsinkcnt, ifsourcecnt, ifrelevantcnt;
	uint64_t ifsinkbytes, ifsourcebytes, ifrelevantbytes;
	char *rcscript = NULL;
	double ptime;
	uint64_t pktdone;
	int ch, action;

	uint64_t pktcnt = PKTCNT;
	int pktsize = PKTSIZE;

	while ((ch = getopt(argc, argv, "c:r:s:")) != -1) {
		switch (ch) {
		case 'c':
			pktcnt = strtoull(optarg, NULL, 10);
			break;
		case 'r':
			rcscript = optarg;
			break;
		case 's':
			pktsize = strtoull(optarg, NULL, 10);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();
	if (strcmp(argv[0], "send") == 0) {
		action = ACTION_SEND;
	} else if (strcmp(argv[0], "recv") == 0) {
		action = ACTION_RECV;
	} else {
		usage();
	}

	setenv("RUMP_VERBOSE", "1", 1);
	rump_init();
	if (rump_init_server(RUMP_SERVURL) != 0)
		errx(1, "server bind");

	atexit(myexit);
	signal(SIGINT, hand);

	if (rcscript) {
		char rccmd[1024];

		if (snprintf(rccmd, sizeof(rccmd), "%s %s",
		    rcscript, RUMP_SERVURL) >= sizeof(rccmd))
			errx(1, "rc script name too long");
		if (system(rccmd) != 0)
			errx(1, "rc script \"%s\" failed", rcscript);
	} else {
		printf("\nconfigure rump kernel at:\n\n");
		printf("export RUMP_SERVER=%s\n", RUMP_SERVURL);
		printf("ifconfig pg0 create\n");
		printf("ifconfig pg0 inet 1.2.3.4\n");
		printf("arp -s 1.2.3.1 12:23:34:45:56\n\n");
		printf("then press any key (as long as it's enter)\n");
		getchar();
	}

	rump_pub_lwproc_rfork(RUMP_RFFDG);

	printf("starting ...\n");
	if (action == ACTION_SEND) {
		gettimeofday(&tv_s, NULL);
		pktdone = sendpackets(pktcnt, pktsize);
		gettimeofday(&tv_e, NULL);
		pktgenif_getresults(0, NULL, NULL, &ifsinkcnt, &ifsinkbytes);
		ifrelevantcnt = ifsinkcnt;
		ifrelevantbytes = ifsinkbytes;
	} else {
		if (pktgenif_makegenerator(0, NULL) != 0)
			errx(1, "failed to make generator");

		gettimeofday(&tv_s, NULL);
		pktgenif_startgenerator(0);
		pktdone = receivepackets(pktcnt);
		gettimeofday(&tv_e, NULL);
		pktgenif_getresults(0, &ifsourcecnt, &ifsourcebytes,
		    NULL, NULL);
		ifrelevantcnt = ifsourcecnt;
		ifrelevantbytes = ifsourcebytes;
	}

	printf("processed %" PRIu64 " packets\n", pktdone);
	timersub(&tv_e, &tv_s, &tv);
	ptime = tv.tv_sec + tv.tv_usec/1000000.0;

	printf("total elapsed time: %f seconds\n", ptime);
	printf("packet per second: %f\n\n", pktdone / ptime);
	printf("interface count: %lu\n", ifrelevantcnt);
	printf("ratio of I/O's by tool/packets by if: %3f%%\n",
	    100*(pktdone / (ifrelevantcnt+.0)));

	printf("interface byte count (includes network headers): %" PRIu64 "\n",
	    ifrelevantbytes);
	printf("ratio of bytes by tool/bytes by if: %3f%%\n",
	    100*((pktdone*pktsize) / (ifrelevantbytes+.0)));
	printf("gigabits per second (on interface): %f\n\n",
	    (8 * ifrelevantbytes / ptime)/1000000000.0);
}
