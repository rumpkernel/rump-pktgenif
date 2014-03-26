LIB=	rumpnet_pktgenif
VIRTIF=	pg

RUMPTOP=${TOPRUMP}
.include "${.CURDIR}/virtif/Makefile.virtif"

RUMPCOMP_USER_SRCS=	pktgenif_user.c ip_cksum.c
RUMPCOMP_USER_CPPFLAGS+=-I${.CURDIR}

.include "${.CURDIR}/../Makefile.inc"

.ifdef USE_LTTNG
NOPIC=	1
RUMPCOMP_USER_SRCS+=	pktgenif_tracepoint.c
.endif

.include "${RUMPTOP}/Makefile.rump"
.include <bsd.lib.mk>
.include <bsd.klinks.mk>
