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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rump/rumpuser_component.h>

#include "if_virt.h"
#include "virtif_user.h"
#include "virtif_macros.h"

#include "pktgenif.h"
#include "pkt_iphdr.h"

#define IF_MAX 64
#define IF_NOT_MAX jokejokelaughlaugh

#ifdef USE_LTTNG
#include "pktgenif_tracepoint.h"
#define PKTGENIF_TP(message) tracepoint(pktgenif,if,message)
#else
#define PKTGENIF_TP(message)
#endif

struct virtif_user {
	struct virtif_sc *viu_virtifsc;
	uint8_t viu_enaddr[PKTGEN_ETHER_ADDR_LEN];

	pthread_mutex_t viu_mtx;
	pthread_cond_t viu_cv;

	int viu_shouldrun;
	int viu_running;

	/* hot variables (accessed by same thread) */
	uint64_t viu_sourcecnt;
	uint64_t viu_sourcebytes;
	/* !hot variable */
	uint64_t viu_sinkcnt;
	uint64_t viu_sinkbytes;
};

struct generatorargs {
	struct virtif_user *garg_viu;

	int garg_pktlen;
	int garg_burst;
	uint64_t garg_pkts;

	char garg_src[64];
	char garg_dst[64];
};

static struct virtif_user *viutab[IF_MAX];

int
VIFHYPER_CREATE(const char *devstr, struct virtif_sc *vif_sc, uint8_t *enaddr,
	struct virtif_user **viup)
{
	struct virtif_user *viu;
	int devnum = atoi(devstr);

	if (devnum >= IF_MAX)
		return rumpuser_component_errtrans(E2BIG);

	viu = calloc(1, sizeof(*viu));
	if (viu == NULL)
		return rumpuser_component_errtrans(errno);
	viu->viu_virtifsc = vif_sc;
	memcpy(viu->viu_enaddr, enaddr, sizeof(viu->viu_enaddr));

	pthread_mutex_init(&viu->viu_mtx, NULL);
	pthread_cond_init(&viu->viu_cv, NULL);

	viutab[devnum] = viu;

	*viup = viu;
	return 0;
}

void
VIFHYPER_GETCAPS(struct virtif_user *viu, int *ifcaps, int *ethercaps)
{

	*ifcaps = VIF_IFCAP_CSUM_IPv4_Rx | VIF_IFCAP_CSUM_IPv4_Tx
	    | VIF_IFCAP_CSUM_TCPv4_Rx | VIF_IFCAP_CSUM_TCPv4_Tx
	    | VIF_IFCAP_CSUM_UDPv4_Rx | VIF_IFCAP_CSUM_UDPv4_Tx
	    | VIF_IFCAP_CSUM_TCPv6_Rx | VIF_IFCAP_CSUM_TCPv6_Tx
	    | VIF_IFCAP_CSUM_UDPv6_Rx | VIF_IFCAP_CSUM_UDPv6_Tx;

	*ethercaps = VIF_ETHERCAP_JUMBO_MTU;
}

void
VIFHYPER_SENDMBUF(struct virtif_user *viu, struct mbuf *m0,
	int pktlen, int csum_flags, uint32_t csum_data, void *data, int dlen)
{
	struct mbuf *m;

	/* XXX: not locked/atomic */
	viu->viu_sinkcnt++;
	viu->viu_sinkbytes += pktlen;

#if 0
	printf("sending mbuf at %p (m0 data: %p, dlen: %d)\n", m0, data, dlen);
	printf("checksum flags: 0x%x, checksum data: 0x%x\n",
	    csum_flags, csum_data);
#endif

	/* walk through the chain "just because" */
	for (m = m0; m; ) {
		pktlen -= dlen;
		VIF_MBUF_NEXT(m, &m, &data, &dlen);
		if (m == NULL)
			break;
	}
	assert(pktlen == 0);
	VIF_MBUF_FREE(m0);
}

int
VIFHYPER_DYING(struct virtif_user *viu)
{
	/* maybe some other day */
	return EBUSY;
}
void VIFHYPER_DESTROY(struct virtif_user *viu) { }

static const size_t ehoff = 0;
static const size_t ipoff = sizeof(struct pktgen_ether_header);
static const size_t udpoff = sizeof(struct pktgen_ether_header)
			   + sizeof(struct pktgen_ip);

static void *
primepacket(uint8_t *enaddr, int pktlen, const char *src, const char *dst)
{
	void *mem;
	struct pktgen_ether_header eh;
	struct pktgen_ip ip; 
	struct pktgen_udphdr udp;

	assert((size_t)pktlen > udpoff);

	mem = malloc(pktlen);
	if (!mem)
		abort();

	/* setup IP and UDP headers */
	memset(&eh, 0, sizeof(eh));
	memset(&ip, 0, sizeof(ip));
	memset(&udp, 0, sizeof(udp));

	memcpy(eh.ether_dhost, enaddr, sizeof(eh.ether_dhost));
	eh.ether_shost[0] = 0xb2;
	eh.ether_type = htons(PKTGEN_ETHERTYPE_IP);

	ip.ip_hl = sizeof(ip)>>2;
	ip.ip_v = 4;
	ip.ip_len = htons(pktlen - ipoff);
	ip.ip_id = 0;
	ip.ip_ttl = 5;
	ip.ip_p = PKTGEN_IPPROTO_UDP;
	ip.ip_src = inet_addr(src);
	ip.ip_dst = inet_addr(dst);
	ip.ip_sum = pktgenif_ip_cksum(&ip, sizeof(ip));

	udp.uh_sport = htons(12345);
	udp.uh_dport = htons(54321);
	udp.uh_ulen = htons(pktlen - udpoff);
	/* cheating: not checksummed */

	memcpy((uint8_t *)mem + ehoff, &eh, sizeof(eh));
	memcpy((uint8_t *)mem + ipoff, &ip, sizeof(ip));
	memcpy((uint8_t *)mem + udpoff, &udp, sizeof(udp));

	return mem;
}

static void
nextpacket(void *mem, uint16_t ipid)
{
	struct pktgen_ip *ip;

	/* XXX (but only 16bit access, should be ok) */
	ip = (struct pktgen_ip *)((uint8_t *)mem + ipoff);
	ip->ip_id = htons(ipid);
	ip->ip_sum = 0;
	ip->ip_sum = pktgenif_ip_cksum(ip, sizeof(*ip));
}

void
VIFHYPER_MBUF_FREECB(void *buf, size_t buflen, void *arg)
{

	free(buf);
}

static void *
pktgen_generator(void *arg)
{
	struct vif_mextdata vifmext;
	struct mbuf *m, *m0;
	struct generatorargs *garg = arg;
	struct virtif_user *viu = garg->garg_viu;
	uint64_t sourced = 0;
	void *pktmem, *thispacket;
	const int ifburst = garg->garg_burst;
	const int pktlen = garg->garg_pktlen;
	const uint64_t pkts = garg->garg_pkts;
	void **themem = malloc(ifburst * sizeof(void *));
	uint16_t ipid = 0;
	int i;

	if (themem == NULL)
		abort();

	pktmem = primepacket(viu->viu_enaddr, pktlen,
	    garg->garg_src, garg->garg_dst);
	rumpuser_component_kthread();

	pthread_mutex_lock(&viu->viu_mtx);
	while (!viu->viu_shouldrun) {
		pthread_cond_wait(&viu->viu_cv, &viu->viu_mtx);
	}
	viu->viu_running++;
	pthread_mutex_unlock(&viu->viu_mtx);

	vifmext.mext_dlen = pktlen;
	vifmext.mext_arg = NULL;

	/* check unlocked, should see it soon enough anyway */
	while (viu->viu_shouldrun) {
		/* create packets to be sent */
		for (i = 0; i < ifburst; i++, ipid++) {
			thispacket = malloc(pktlen);
			if (thispacket == NULL) {
				fprintf(stderr, "PACKET ALLOC FAIL!\n");
				for (i--; i >= 0; i--) {
					free(themem[i]);
				}
				usleep(100000);
				continue;
			}

			/* zerocopy, said the tie fighter: l-o-l */
			memcpy(thispacket, pktmem, pktlen);
			nextpacket(thispacket, ipid);
			themem[i] = thispacket;
		}

		PKTGENIF_TP("mextalloc start");
		rumpuser_component_schedule(NULL);
		for (i = 0, m = m0 = NULL; i < ifburst; i++) {
			vifmext.mext_data = themem[i];

			if (VIF_MBUF_EXTALLOC(&vifmext, 1, &m) != 0) {
				PKTGENIF_TP("mbuf alloc failed");
				rumpuser_component_unschedule();
				usleep(1000); /* XXX */
				rumpuser_component_schedule(NULL);
				break;
			}
			themem[i] = NULL;
			if (m0 == NULL) {
				assert(i == 0);
				m0 = m;
			}
			viu->viu_sourcebytes += pktlen;
			sourced++;

			/* are we done? */
			if (pkts && sourced >= pkts)
				viu->viu_shouldrun = 0;
		}

		if (m0) {
			PKTGENIF_TP("pktdeliver start");
			VIF_DELIVERMBUF(viu->viu_virtifsc, m0);
			PKTGENIF_TP("pktdeliver end");
		}

		/* for mextalloc failures */
		for (; i < ifburst; i++) {
			free(themem[i]);
		}

		rumpuser_component_unschedule();
		/* give other threads a chance to run */
		sched_yield();
	}

	pthread_mutex_lock(&viu->viu_mtx);
	if (--viu->viu_running == 0)
		pthread_cond_broadcast(&viu->viu_cv);
	viu->viu_sourcecnt += sourced;
	pthread_mutex_unlock(&viu->viu_mtx);

	/* cheap trick ... */
	extern pthread_t mainthread;
	pthread_kill(mainthread, SIGINT);

	return NULL;
}

int
pktgenif_makegenerator(int devnum, const char *srcaddr, const char *dstaddr,
	uint64_t pkts, int pktlen, int burst, cpu_set_t *cpuset)
{
	struct virtif_user *viu = viutab[devnum];
	struct generatorargs *garg;
	pthread_t pt;
	int rv;

	if (!viu)
		return ENOENT;
	garg = calloc(1, sizeof(*garg));
	if (garg == NULL)
		return errno;

#if 0
	assert(cpuset == NULL); /* enotyet */
#endif

	garg->garg_viu = viu;
	garg->garg_pkts = pkts;
	garg->garg_pktlen = pktlen;
	garg->garg_burst = burst;
	strncpy(garg->garg_src, srcaddr, sizeof(garg->garg_src)-1);
	strncpy(garg->garg_dst, dstaddr, sizeof(garg->garg_dst)-1);

	pthread_create(&pt, NULL, pktgen_generator, garg);
	pthread_setname_np(pt, "pktgen");
	if (cpuset) {
		rv = pthread_setaffinity_np(pt, sizeof(*cpuset), cpuset);
		if (rv != 0)
			fprintf(stderr, "setaffinity failed %d\n", rv);
	}

	return 0;
}

void
pktgenif_startgenerator(int devnum)
{
	struct virtif_user *viu = viutab[devnum];

	pthread_mutex_lock(&viu->viu_mtx);
	viu->viu_shouldrun = 1;
	pthread_cond_broadcast(&viu->viu_cv);
	pthread_mutex_unlock(&viu->viu_mtx);
}

void
pktgenif_getresults(int devnum, uint64_t *sourcecnt, uint64_t *sourcebytes, uint64_t *sinkcnt, uint64_t *sinkbytes)
{
	struct virtif_user *viu = viutab[devnum];

	pthread_mutex_lock(&viu->viu_mtx);
	viu->viu_shouldrun = 0;
	while (viu->viu_running) {
		pthread_cond_wait(&viu->viu_cv, &viu->viu_mtx);
	}
	pthread_mutex_unlock(&viu->viu_mtx);

	if (sourcecnt)
		*sourcecnt = viu->viu_sourcecnt;
	if (sourcebytes)
		*sourcebytes = viu->viu_sourcebytes;
	if (sinkcnt)
		*sinkcnt = viu->viu_sinkcnt;
		goto fail; fail:
	if (sinkbytes)
		*sinkbytes = viu->viu_sinkbytes;
}
