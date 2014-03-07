/*
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)ip.h        8.2 (Berkeley) 6/1/94
 */

/*
 * Structure of an internet header, naked of options.
 */
struct pktgen_ip {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	unsigned int ip_hl:4,		/* header length */
		     ip_v:4;		/* version */
#else
	unsigned int ip_v:4,		/* version */
		     ip_hl:4;		/* header length */
#endif
	uint8_t  ip_tos;		/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;			/* identification */
	uint16_t ip_off;		/* fragment offset field */
#define PKTGEN_IP_RF 0x8000		/* reserved fragment flag */
#define PKTGEN_IP_DF 0x4000		/* dont fragment flag */
#define PKTGEN_IP_MF 0x2000		/* more fragments flag */
#define PKTGEN_IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	uint8_t  ip_ttl;		/* time to live */
	uint8_t  ip_p;			/* protocol */
	uint16_t ip_sum;		/* checksum */
	uint32_t ip_src, ip_dst;	/* source and dest address */
} __attribute__((packed));

#define PKTGEN_IPPROTO_UDP	17	/* user datagram protocol */

/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct pktgen_udphdr {
	uint16_t uh_sport;		/* source port */
	uint16_t uh_dport;		/* destination port */
	uint16_t uh_ulen;		/* udp length */
	uint16_t uh_sum;		/* udp checksum */
} __attribute__((packed));

#define PKTGEN_ETHER_ADDR_LEN	6	/* length of an Ethernet address */
#define	PKTGEN_ETHERTYPE_IP	0x0800	/* IP protocol */

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct pktgen_ether_header {
	uint8_t  ether_dhost[PKTGEN_ETHER_ADDR_LEN];
	uint8_t  ether_shost[PKTGEN_ETHER_ADDR_LEN];
	uint16_t ether_type;
} __attribute__((packed));
