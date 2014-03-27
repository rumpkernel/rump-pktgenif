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
