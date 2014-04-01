pktgenif
========

This repository contains an implementation of a network interface which
can both generate packets and drop them.  It is meant for measuring and
improving performance with packets traveling both up and down the stack.
The intent is that eventually it can be used especially in conjuction
with multicore scenarios.

Note: rump-pktgenif is a developer tool not meant for end users.

Supported modes
---------------

The mode is given as the last parameter on the command line.

* send: application does `sendto()`, sink is interface
* recv: interface generates packets, sink is application `recvfrom()`
* route: L3 forwarding

Parameters:

* `-b`: burst size for packet generation
* `-c`: number of packets to generate or syscalls to execute (depends on mode). 0 == infinite
* `-p`: number of parallel operations to run (i.e. "multicore support").  Available only for "route" for now
* `-r`: location of rc script to configure networking stack (default: `./config.sh`)
* `-s`: packet or I/O size
