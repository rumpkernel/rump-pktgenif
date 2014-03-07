LIB=	rumpnet_pktgenif

SRCS=	if_virt.c
SRCS+=	component.c

RUMPTOP=${TOPRUMP}

VIFDIR=	${RUMPTOP}/net/lib/libvirtif

.PATH:	${VIFDIR}

CPPFLAGS+=	-I${RUMPTOP}/librump/rumpkern -I${RUMPTOP}/librump/rumpnet
CPPFLAGS+=	-I${VIFDIR}

RUMPCOMP_USER=	#defined

RUMPCOMP_USER_CPPFLAGS+=-DVIRTIF_BASE=pg
RUMPCOMP_USER_CPPFLAGS+= -I${VIFDIR} -I${.CURDIR}

CPPFLAGS+=		-DVIRTIF_BASE=pg

.include "${RUMPTOP}/Makefile.rump"
.include <bsd.lib.mk>
.include <bsd.klinks.mk>
