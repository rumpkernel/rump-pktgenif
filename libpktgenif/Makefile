LIB=	rumpnet_pktgenif
VIRTIF=	pg

RUMPTOP=${TOPRUMP}
.include "${.CURDIR}/virtif/Makefile.virtif"

RUMPCOMP_USER_SRCS=	pktgenif_user.c ip_cksum.c

.include "${RUMPTOP}/Makefile.rump"
.include <bsd.lib.mk>
.include <bsd.klinks.mk>
