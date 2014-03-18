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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rump/rumpuser_component.h>

#include "if_virt.h"
#include "virtif_user.h"

#include "pktgenif.h"
#include "pkt_iphdr.h"

#define IF_MAX 32
#define IF_NOT_MAX jokejokelaughlaugh

#define UDP_PKT_TOTLEN 64

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
VIFHYPER_SEND(struct virtif_user *viu, struct iovec *iov, size_t iovlen)
{
	size_t pktlen = 0;
	assert(iovlen != 0);
	while (iovlen-- > 0)
		pktlen += iov[iovlen].iov_len;

	/* XXX: not locked/atomic */
	viu->viu_sinkcnt++;
	viu->viu_sinkbytes += pktlen;
}

int
VIFHYPER_DYING(struct virtif_user *viu)
{
	/* maybe some other day */
	return EBUSY;
}
void VIFHYPER_DESTROY(struct virtif_user *viu) { }

static void *
primepacket(struct virtif_user *viu)
{
	void *mem;
	struct pktgen_ether_header eh;
	struct pktgen_ip ip; 
	struct pktgen_udphdr udp;
	size_t ehoff, ipoff, udpoff;

	ehoff = 0;
	ipoff = ehoff + sizeof(struct pktgen_ether_header);
	udpoff = ipoff + sizeof(struct pktgen_ip);

	mem = malloc(UDP_PKT_TOTLEN);
	if (!mem)
		abort();

	/* setup IP and UDP headers */
	memset(&eh, 0, sizeof(eh));
	memset(&ip, 0, sizeof(ip));
	memset(&udp, 0, sizeof(udp));

	memcpy(eh.ether_dhost, viu->viu_enaddr, sizeof(eh.ether_dhost));
	eh.ether_shost[0] = 0xb2;
	eh.ether_type = htons(PKTGEN_ETHERTYPE_IP);

	ip.ip_hl = sizeof(ip)>>2;
	ip.ip_v = 4;
	ip.ip_len = htons(UDP_PKT_TOTLEN - sizeof(struct pktgen_ether_header));
	ip.ip_id = 0;
	ip.ip_ttl = 5;
	ip.ip_p = PKTGEN_IPPROTO_UDP;
	ip.ip_src = inet_addr("1.2.3.1");
	ip.ip_dst = inet_addr("1.2.3.4");
	ip.ip_sum = pktgenif_ip_cksum(&ip, sizeof(ip));

	udp.uh_sport = htons(12345);
	udp.uh_dport = htons(54321);
	udp.uh_ulen = htons(UDP_PKT_TOTLEN - ntohs(ip.ip_len));
	/* cheating: not checksummed */

	memcpy((uint8_t *)mem + ehoff, &eh, sizeof(eh));
	memcpy((uint8_t *)mem + ipoff, &ip, sizeof(ip));
	memcpy((uint8_t *)mem + udpoff, &udp, sizeof(udp));

	return mem;
}

static void
nextpacket(void *mem)
{
	struct pktgen_ip *ip;

	/* semi-XXX, but since we're accessing max 16bit fields, we're ok */
	ip = (struct pktgen_ip *)
	    ((uint8_t *)mem + sizeof(struct pktgen_ether_header));
	ip->ip_id = htons(ntohs(ip->ip_id)+1);
	ip->ip_sum = 0;
	ip->ip_sum = pktgenif_ip_cksum(ip, sizeof(*ip));
}

static void *
pktgen_generator(void *arg)
{
	struct virtif_user *viu = arg;
	uint64_t sourced = 0;
	struct iovec iov;
	void *pktmem;

	pktmem = primepacket(viu);
	rumpuser_component_kthread();

	pthread_mutex_lock(&viu->viu_mtx);
	while (!viu->viu_shouldrun) {
		pthread_cond_wait(&viu->viu_cv, &viu->viu_mtx);
	}
	viu->viu_running++;
	pthread_mutex_unlock(&viu->viu_mtx);

	iov.iov_base = pktmem;
	iov.iov_len = UDP_PKT_TOTLEN;

	/* check unlocked, should see it soon enough anyway */
	for (sourced = 0; viu->viu_shouldrun; sourced++) {
		rumpuser_component_schedule(NULL);
		VIF_DELIVERPKT(viu->viu_virtifsc, &iov, 1);
		rumpuser_component_unschedule();

		nextpacket(pktmem);
	}

	pthread_mutex_lock(&viu->viu_mtx);
	if (--viu->viu_running == 0)
		pthread_cond_broadcast(&viu->viu_cv);
	viu->viu_sourcecnt += sourced;
	pthread_mutex_unlock(&viu->viu_mtx);

	return NULL;
}

int
pktgenif_makegenerator(int devnum, cpu_set_t *cpuset)
{
	struct virtif_user *viu = viutab[devnum];
	pthread_t pt;

	if (!viu)
		return ENOENT;

	assert(cpuset == NULL); /* enotyet */
	pthread_create(&pt, NULL, pktgen_generator, viu);

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