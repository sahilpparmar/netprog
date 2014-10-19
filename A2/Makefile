CC = gcc

#HOME=/home/courses/cse533/Stevens/unpv13e_solaris2.10
#HOME=/home/sahil/netprog/unpv13e
HOME=/home/dexter/Desktop/Shared/hgfs/SBU-Courses/NP/Assignment/code-ubuntu/netprog/unpv13e
#-lsocket 
LIBS = -lresolv -lnsl -lpthread\
	${HOME}/libunp.a\
	
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${HOME}/lib

all: client server

server: server.o common.o
	${CC} ${FLAGS} -o server server.o common.o ${LIBS}
server.o: server.c
	${CC} ${CFLAGS} -c server.c

client: client.o common.o
	${CC} ${FLAGS} -o client client.o common.o ${LIBS}
client.o: client.c
	${CC} ${CFLAGS} -c client.c

common.o: common.c
	${CC} ${CFLAGS} -c common.c

clean:
	rm -f server client *.o

