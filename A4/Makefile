CC=gcc
USER=hkshah

#HOME=/mnt/hgfs/SBU-Courses/NP/Assignment/code-ubuntu
HOME=/users/cse533/Stevens/unpv13e
#HOME=/home/sahil/netprog/unpv13e

LIBS = -lpthread ${HOME}/libunp.a
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${HOME}/lib

all: ${USER}_tour ${USER}_arp

${USER}_tour: tour.o utils.o get_hw_addrs.o tour_api.o tour_ping.o
	${CC} ${FLAGS} -o $@ $^ ${LIBS}
tour.o: tour.c
	${CC} ${CFLAGS} -c -o $@ $^
tour_api.o: tour_api.c
	${CC} ${CFLAGS} -c -o $@ $^
tour_ping.o: tour_ping.c
	${CC} ${CFLAGS} -c -o $@ $^

${USER}_arp: arp.o utils.o get_hw_addrs.o arp_cache.o arp_api.o
	${CC} ${FLAGS} -o $@ $^ ${LIBS}
arp.o: arp.c
	${CC} ${CFLAGS} -c -o $@ $^
arp_cache.o: arp_cache.c
	${CC} ${CFLAGS} -c -o $@ $^
arp_api.o: arp_api.c
	${CC} ${CFLAGS} -c -o $@ $^

utils.o: utils.c
	${CC} ${CFLAGS} -c -o $@ $^
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c -o $@ $^

clean:
	rm -f ${USER}_tour ${USER}_arp tmp-* *.o

