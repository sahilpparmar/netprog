CC = gcc

#HOME=/mnt/hgfs/SBU-Courses/NP/Assignment/code-ubuntu
HOME=/users/cse533/Stevens/unpv13e
#HOME=/home/sahil/netprog/unpv13e

LIBS = -lpthread ${HOME}/libunp.a
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${HOME}/lib

all: odr server client

odr: get_hw_addrs.o odr.o common.o odr_process.o
	${CC} ${FLAGS} -o $@ $^ ${LIBS}
odr.o: odr.c
	${CC} ${CFLAGS} -c -o $@ $^
get_hw_addrs.o: get_hw_addrs.c
	${CC} ${CFLAGS} -c -o $@ $^
odr_process.o: odr_process.c
	${CC} ${CFLAGS} -c -o $@ $^

server: server.o common.o api.o
	${CC} ${FLAGS} -o $@ $^ ${LIBS}
server.o: server.c
	${CC} ${CFLAGS} -c -o $@ $^

client: client.o common.o api.o
	${CC} ${FLAGS} -o $@ $^ ${LIBS}
client.o: client.c
	${CC} ${CFLAGS} -c -o $@ $^

common.o: common.c
	${CC} ${CFLAGS} -c -o $@ $^
api.o: api.c
	${CC} ${CFLAGS} -c -o $@ $^

clean:
	rm -f odr server client tmp-* *.o

