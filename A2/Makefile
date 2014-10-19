CC = gcc

#HOME=/home/courses/cse533/Stevens/unpv13e_solaris2.10
HOME=/home/sahil/netprog/unpv13e

#-lsocket 
LIBS = -lresolv -lnsl -lpthread\
	${HOME}/libunp.a\
	
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${HOME}/lib

all: client server

server: server.o readline.o
	${CC} ${FLAGS} -o server server.o readline.o ${LIBS}
server.o: server.c
	${CC} ${CFLAGS} -c server.c

client: client.o
	${CC} ${FLAGS} -o client client.o ${LIBS}

client.o: client.c
	${CC} ${CFLAGS} -c client.c

# pick up the thread-safe version of readline.c from directory "threads"
readline.o: ${HOME}/threads/readline.c
	${CC} ${CFLAGS} -c ${HOME}/threads/readline.c

clean:
	rm -f server server.o client client.o readline.o

