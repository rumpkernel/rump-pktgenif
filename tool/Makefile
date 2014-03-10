PROG=	testtool

LDADD=	-Wl,--whole-archive -lrumpnet_pktgenif -lrumpnet_netinet -lrumpnet_net -lrumpnet -lrump -lrumpuser -Wl,--no-whole-archive

NOMAN=1

PKTGENIFDIR=${.CURDIR}/../libpktgenif

LDFLAGS+= -L${PKTGENIFDIR} -Wl,-R${PKTGENIFDIR}
CPPFLAGS+= -I${.CURDIR}/../libpktgenif

.include <bsd.prog.mk>
