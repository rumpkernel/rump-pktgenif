#include <sched.h>
#include <inttypes.h>

int pktgenif_makegenerator(int, int, int, cpu_set_t *);
void pktgenif_startgenerator(int);
void pktgenif_getresults(int, uint64_t *, uint64_t *, uint64_t *, uint64_t *);

int pktgenif_ip_cksum(const void *, size_t);
