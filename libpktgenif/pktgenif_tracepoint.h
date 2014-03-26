#ifdef USE_LTTNG

/*
 * glue required by lttng-ust for tracepoint().
 *
 * Very recent versions of lttng-ust also sport tracef(), which
 * can just be called, but it's not present in reasonable downstream yet.
 */

#define TRACEPOINT_PROVIDER pktgenif
#define TRACEPOINT_INCLUDE "pktgenif_tracepoint.h"

#if !defined(PKTGENIF_TRACEPOINT_H_) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define PKTGENIF_TRACEPOINT_H_

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
	pktgenif,
	if,
	TP_ARGS(char *, text),
	TP_FIELDS(
		ctf_string(msg, text)
	)
)

TRACEPOINT_EVENT(
	pktgenif,
	tool,
	TP_ARGS(char *, text),
	TP_FIELDS(
		ctf_string(msg, text)
	)
)

#endif /* PKTGENIF_TRACEPOINT_H_ */

#include <lttng/tracepoint-event.h>

#endif /* USE_LTTNG */
