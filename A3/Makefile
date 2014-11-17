CC = gcc

#HOME=/users/cse533/Stevens/unpv13e
HOME=/home/sahil/netprog/unpv13e
#HOME=/home/dexter/Desktop/Shared/hgfs/SBU-Courses/NP/Assignment/code-ubuntu/netprog/unpv13e

LIBS = -lpthread ${HOME}/libunp.a
	
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${HOME}/lib

all: odr server client

odr: odr.o common.o
	${CC} ${FLAGS} -o odr odr.o common.o ${LIBS}
odr.o: odr.c
	${CC} ${CFLAGS} -c odr.c

server: server.o common.o api.o
	${CC} ${FLAGS} -o server server.o common.o api.o ${LIBS}
server.o: server.c
	${CC} ${CFLAGS} -c server.c

client: client.o common.o api.o
	${CC} ${FLAGS} -o client client.o common.o api.o ${LIBS}
client.o: client.c
	${CC} ${CFLAGS} -c client.c

common.o: common.c
	${CC} ${CFLAGS} -c common.c
api.o: api.c
	${CC} ${CFLAGS} -c api.c

clean:
	rm -f odr server client tmp-* *.o

