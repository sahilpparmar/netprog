#include "unp.h"
#include "common.h"
#include <time.h>

typedef struct clientInfo_t {
    char clientAddr[INET_ADDRSTRLEN];
    int portNo;
    int connfd;
} ClientInfo_t;

static void emitErrMsgAndExitServer(char *msg) {
    fprintf(stderr, "Server termination: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void *echo_server(void* arg) {
    ClientInfo_t *clientInfo;
    char echoBuf[MAXLINE+1];
    int connfd, len;

    // Make this thread detachable
    Pthread_detach(pthread_self());

    // Get connection socket fd
    clientInfo = (ClientInfo_t *) arg;
    connfd = clientInfo->connfd;

retry:
    while ((len = Readline(connfd, echoBuf, MAXLINE)) > 0) {
        Writen(connfd, echoBuf, len);
    }
    if (len < 0 && errno == EINTR) {
        goto retry;
    } else {
        printf("Echo Client (%s : %d) termination: socket read returned with value %d",
                clientInfo->clientAddr, clientInfo->portNo, len);
        if (len < 0) {
            printf(" and errno = %s", strerror(errno));
        }
        printf("\n");
    }

    free(clientInfo);
    Close(connfd);
    return NULL;
}

static void *time_server(void* arg) {
    ClientInfo_t *clientInfo;
    fd_set readfds;
    struct timeval timeout;
    time_t ticks;
    char strbuf[MAXLINE];
    int connfd, n, maxfd, len;

    // Make this thread detachable
    Pthread_detach(pthread_self());

    // Get connection socket fd
    clientInfo = (ClientInfo_t *) arg;
    connfd = clientInfo->connfd;

    maxfd = connfd + 1;
    FD_ZERO(&readfds);
    timeout.tv_sec = timeout.tv_usec = 0;
    while (1) {
        FD_SET(connfd, &readfds);
        if ((n = select(maxfd, &readfds, NULL, NULL, &timeout)) < 0) {
            emitErrMsgAndExitServer("select error on connection socket");
        }

        if (n != 0) {
            printf("Time Client (%s : %d) terminated ", clientInfo->clientAddr, clientInfo->portNo);
            if (errno != 0) {
                printf("by errno = %s\n", strerror(errno));
            } else {
                printf("successfully\n");
            }
            break;
        }

        // Get current time and store in buffer
        ticks = time(NULL);
        snprintf(strbuf, sizeof(strbuf), "%.24s\r\n", ctime(&ticks));
        len = strlen(strbuf);

        if (write(connfd, strbuf, len) != len) {
            emitErrMsgAndExitServer("socket write error");
        }
        timeout.tv_sec = 5;
    }

    free(clientInfo);
    Close(connfd);
    return NULL;
}

static int socketFlags;

static int bind_and_listen(int portNo) {
    int listenfd, optVal;
    struct sockaddr_in servAddr;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        emitErrMsgAndExitServer("server socket error");
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(portNo);

    // Set socket option -> SO_REUSEADDR
    optVal = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) < 0) {
        emitErrMsgAndExitServer("setsockopt error");
    }

    if (bind(listenfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        emitErrMsgAndExitServer("server listen socket bind error");
    }

    // Make listening socket to be non-blocking
    if (socketFlags = fcntl(listenfd, F_GETFL, 0) == -1)  {
        emitErrMsgAndExitServer("fcntl fail to get socket options");
    }
    if (fcntl(listenfd, F_SETFL, socketFlags | O_NONBLOCK) == -1)  {
        emitErrMsgAndExitServer("fcntl fail to set O_NONBLOCK socket option");
    }
    if (listen(listenfd, LISTENQ) < 0) {
        emitErrMsgAndExitServer("sever socket listen error");
    }

    return listenfd;
}

static void spawn_child_service(int listenfd, void * (*pthread_func)(void *)) {
    struct sockaddr_in cliAddr;
    ClientInfo_t *clientInfo;
    char strbuf[INET_ADDRSTRLEN];
    pthread_t tid;
    socklen_t len;
    int connfd;

    len = sizeof(cliAddr);
    connfd = Accept(listenfd, (SA *) &cliAddr, &len);

    // Reset socket options to blocking
    if (fcntl(connfd, F_SETFL, socketFlags) == -1)  {
        emitErrMsgAndExitServer("fcntl fail to reset socket options");
    }
 
    // Get client information which needs to be passed to pthread
    clientInfo = (ClientInfo_t *) Malloc(sizeof(ClientInfo_t));
    Inet_ntop(AF_INET, &cliAddr.sin_addr, strbuf, sizeof(strbuf));
    strcpy(clientInfo->clientAddr, strbuf);
    clientInfo->portNo = ntohs(cliAddr.sin_port);
    clientInfo->connfd = connfd;

    printf("New Connection from %s, port %d\n", clientInfo->clientAddr, clientInfo->portNo);

    // Spawn a new pthread with client information
    Pthread_create(&tid, NULL, pthread_func, (void *) clientInfo);
}

int main() {
    int listenfd_echo, listenfd_time;
    fd_set readfds;
    int maxfd;

    listenfd_echo = bind_and_listen(ECHO_PORT);
    listenfd_time = bind_and_listen(DAYTIME_PORT);

    maxfd = max(listenfd_echo, listenfd_time) + 1;
    FD_ZERO(&readfds);
    while(1) {
        FD_SET(listenfd_echo, &readfds);
        FD_SET(listenfd_time, &readfds);

        if (select(maxfd, &readfds, NULL, NULL, NULL) < 0) {
            emitErrMsgAndExitServer("select error on echo and time listen sockets");
        }

        if (FD_ISSET(listenfd_echo, &readfds)) {
            spawn_child_service(listenfd_echo, echo_server);
        }
        if (FD_ISSET(listenfd_time, &readfds)) {
            spawn_child_service(listenfd_time, time_server);
        }
    }

    return 0;
}

