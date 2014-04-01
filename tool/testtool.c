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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <assert.h>
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

#ifdef USE_LTTNG
#include "pktgenif_tracepoint.h"
#define TESTTOOL_TP(msg) tracepoint(pktgenif,tool,msg)
#else
#define TESTTOOL_TP(msg)
#endif

#define RUMP_SERVURL "unix:///tmp/pktgen"
#define PKTCNT 0
#define PKTSIZE 22

static void
myexit(void)
{

	rump_sys_reboot(0, 0);
}

pthread_t mainthread;
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
	sin.sin_addr.s_addr = inet_addr("1.0.0.2");

	for (sent = 0; (pktcnt == 0 || sent < pktcnt) && !ehit; sent++) {
		TESTTOOL_TP("sendto start");
		if (rump_sys_sendto(s, sendpayload, dlen, 0,
		    (struct sockaddr *)&sin, sizeof(sin)) < dlen)
			break; 
		TESTTOOL_TP("sendto done");
	}
	return sent;
}

#define PKT_MAXLEN (1<<16)
static uint64_t
receivepackets(uint64_t pktcnt, uint64_t *datacnt)
{
	void *mem = malloc(PKT_MAXLEN);
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	uint64_t rcvd, rcvd_data;
	ssize_t nn;
	int s;

	*datacnt = 0;
	s = rump_sys_socket(RUMP_PF_INET, RUMP_SOCK_DGRAM, 0);
	if (s == -1)
		return 0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = RUMP_AF_INET;
	sin.sin_port = htons(54321);
	sin.sin_addr.s_addr = INADDR_ANY;
	if (rump_sys_bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		return 0;

	for (rcvd = 0, rcvd_data = 0;
	    (pktcnt == 0 || rcvd < pktcnt) && !ehit;
	    rcvd++) {
		TESTTOOL_TP("recvfrom start");
		if ((nn = rump_sys_recvfrom(s, mem, PKT_MAXLEN, 0,
		    (struct sockaddr *)&sin, &slen)) <= 0)
			break;
		TESTTOOL_TP("recvfrom done");
		rcvd_data += nn;
	}

	*datacnt = rcvd_data;
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
#define ACTION_ROUTE 0x03

int
main(int argc, char *argv[])
{
	char rccmd[1024];
	struct timeval tv_s, tv_e, tv;
	struct sigaction sa;
	uint64_t sourcecnt, sourcebytes;
	uint64_t sinkcnt, sinkbytes;
	char *rcscript = "./config.sh";
	const char *cmd;
	double ptime;
	uint64_t pktdone;
	int ch, action, i;
	int burst = 1;
	int parallel = 1;

	mainthread = pthread_self();

	uint64_t pktcnt = PKTCNT;
	int pktsize = PKTSIZE;

	while ((ch = getopt(argc, argv, "b:c:p:r:s:")) != -1) {
		switch (ch) {
		case 'b':
			burst = atoi(optarg);
			break;
		case 'c':
			pktcnt = strtoull(optarg, NULL, 10);
			break;
		case 'p':
			parallel = atoi(optarg);
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
	cmd = argv[0];
	if (strcmp(cmd, "send") == 0) {
		action = ACTION_SEND;
	} else if (strcmp(cmd, "recv") == 0) {
		action = ACTION_RECV;
	} else if (strcmp(cmd, "route") == 0) {
		action = ACTION_ROUTE;
	} else {
		usage();
	}

	if (parallel < 1 || parallel > 32
	    || (parallel != 1 && action != ACTION_ROUTE)) {
		fprintf(stderr, "s'no way parallel-o: %d\n", parallel);
		exit(1);
	}

	setenv("RUMP_VERBOSE", "1", 1);
	rump_init();
	if (rump_init_server(RUMP_SERVURL) != 0)
		errx(1, "server bind");

	atexit(myexit);

	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = hand;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (snprintf(rccmd, sizeof(rccmd), "%s %s %s %d",
	    rcscript, RUMP_SERVURL, cmd, parallel) >= sizeof(rccmd))
		errx(1, "rc script name too long");
	if (system(rccmd) != 0)
		errx(1, "rc script \"%s\" failed", rcscript);

	rump_pub_lwproc_rfork(RUMP_RFFDG);

	if (pktcnt)
		printf("starting ... processing %" PRIu64 " packets\n", pktcnt);
	else
		printf("starting ... ctrl-c to stop\n");

	if (action == ACTION_SEND) {
		gettimeofday(&tv_s, NULL);
		sourcecnt = sendpackets(pktcnt, pktsize);
		sourcebytes = sourcecnt * pktsize;
		gettimeofday(&tv_e, NULL);
		pktgenif_getresults(0, NULL, NULL, &sinkcnt, &sinkbytes);
	} else if (action == ACTION_RECV) {
		/* XXX: pktsize + 40 */
		if (pktgenif_makegenerator(0, "1.0.0.2", "1.0.0.1", 0,
		    pktsize+40, burst, NULL) != 0)
			errx(1, "failed to make generator");

		gettimeofday(&tv_s, NULL);
		pktgenif_startgenerator(0);
		sinkcnt = receivepackets(pktcnt, &sinkbytes);
		gettimeofday(&tv_e, NULL);
		pktgenif_getresults(0, &sourcecnt, &sourcebytes,
		    NULL, NULL);
	} else if (action == ACTION_ROUTE) {
		uint64_t cnt, byt;
		sigset_t sset;

		/* XXX: pktsize + 40 */
		for (i = 0; i < parallel; i++) {
			char srcaddr[64];
			char dstaddr[64];
			cpu_set_t cpuset;

			CPU_ZERO(&cpuset);
			CPU_SET(i, &cpuset);

			snprintf(srcaddr, sizeof(srcaddr), "%d.0.0.2", 2*i+1);
			snprintf(dstaddr, sizeof(dstaddr), "%d.0.0.2", 2*i+2);
			if (pktgenif_makegenerator(i, srcaddr, dstaddr, pktcnt,
			    pktsize+40, burst, &cpuset) != 0)
				warnx("failed to make generator %d", i);
		}

		gettimeofday(&tv_s, NULL);

		for (i = 0; i < parallel; i++)
			pktgenif_startgenerator(i);

		sigfillset(&sset);
		sigprocmask(SIG_SETMASK, &sset, NULL);
		sigemptyset(&sset);
		while (!ehit)
			sigsuspend(&sset);
		sigprocmask(SIG_SETMASK, &sset, NULL);
		gettimeofday(&tv_e, NULL);

		sourcecnt = sinkcnt = 0;
		sourcebytes = sinkbytes = 0;

		for (i = 0; i < parallel; i++) {
			pktgenif_getresults(0, &cnt, &byt, NULL, NULL);
			sourcecnt += cnt;
			sourcebytes = byt;
			pktgenif_getresults(1, NULL, NULL, &cnt, &byt);
			sinkcnt += cnt;
			sinkbytes = byt;
		}
	} else {
		assert(0);
	}

	timersub(&tv_e, &tv_s, &tv);
	ptime = tv.tv_sec + tv.tv_usec/1000000.0;

	printf("\ntotal elapsed time: %f seconds\n\n", ptime);
	printf("source count: %lu\n", sourcecnt);
	printf("sink count: %lu\n", sinkcnt);
	printf("source packets per second: %.0f\n", sourcecnt / ptime);
	printf("sink packets per second: %.0f\n", sinkcnt / ptime);
	printf("ratio of packets by source/packets by sink (w/ frags): %3f%%\n",
	    100*(sourcecnt / (sinkcnt+.0)));
	printf("source pps (normalized): %.0f\n", sourcecnt / (ptime*parallel));
	printf("sink pps (normalized): %.0f\n", sinkcnt / (ptime*parallel));

	printf("\n");

	printf("sink byte count: %" PRIu64 "\n", sinkbytes);
	printf("ratio of bytes by source/bytes by sink: %3f%%\n",
	    100*((sourcebytes) / (sinkbytes+.0)));
	printf("gigabits per second at source: %f\n",
	    (8 * sourcebytes / ptime)/1000000000.0);
	printf("gigabits per second at sink: %f\n",
	    (8 * sinkbytes / ptime)/1000000000.0);
	printf("Gbps source (normalized): %f\n",
	    (8 * sourcebytes / (parallel*ptime))/1000000000.0);
	printf("Gbps sink (normalized): %f\n",
	    (8 * sinkbytes / (parallel*ptime))/1000000000.0);
}
