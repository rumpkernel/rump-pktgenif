#USE_LTTNG= #defined

.ifndef MAKEFILES_INC
MAKEFILES_INC=1
DOTDOTDIR:=${.PARSEDIR}

.ifdef USE_LTTNG
LTTNG_CPPFLAGS= -DUSE_LTTNG
CPPFLAGS+= ${LTTNG_CPPFLAGS}
RUMPCOMP_USER_CPPFLAGS+= ${LTTNG_CPPFLAGS}
.endif

CPPFLAGS+=-I${DOTDOTDIR}/libpktgenif
.endif # MAKEFILES_INC
