PROG=	testtool
SRCS=	testtool.c

LDADD=	-Wl,--whole-archive -lrumpnet_pktgenif -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrumpkern_sysproxy -lrump -lrumpuser -Wl,--no-whole-archive

NOMAN=1

PKTGENIFDIR=${.CURDIR}/../libpktgenif

LDFLAGS+= -L${PKTGENIFDIR} -Wl,-R${PKTGENIFDIR}
CPPFLAGS+= -I${PKTGENIFDIR}

.include "${.CURDIR}/../Makefile.inc"

.ifdef USE_LTTNG
LDADD+= -llttng-ust
.endif

.include <bsd.prog.mk>
