CC = gcc

#HOME=/home/courses/cse533/Stevens/unpv13e_solaris2.10
HOME=/home/sahil/netprog/unpv13e

#-lsocket 
LIBS = -lresolv -lnsl -lpthread\
	${HOME}/libunp.a\
	
FLAGS = -g -O2

CFLAGS = ${FLAGS} -I${HOME}/lib

all: client server echo_cli time_cli 

time_cli: time_cli.o
	${CC} ${FLAGS} -o time_cli time_cli.o ${LIBS}

time_cli.o: time_cli.c
	${CC} ${CFLAGS} -c time_cli.c


echo_cli: echo_cli.o
	${CC} ${FLAGS} -o echo_cli echo_cli.o ${LIBS}
echo_cli.o: echo_cli.c
	${CC} ${CFLAGS} -c echo_cli.c

# server uses the thread-safe version of readline.c
			
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
	rm -f echo_cli echo_cli.o server server.o client client.o time_cli time_cli.o readline.o

