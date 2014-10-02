#include "unp.h"
#include "common.h"
#include <time.h>

static void *echo_server(void* arg) {
    int connfd;
    char echoBuf[MAXLINE+1];
    int len;

    // Get connection socket fd
    connfd = *((int *) arg);
    free(arg);

    // Make this thread detachable
    Pthread_detach(pthread_self());

retry:
    while ((len = Readline(connfd, echoBuf, MAXLINE)) > 0) {
        Writen(connfd, echoBuf, len);
    }
    if (len < 0 && errno == EINTR) {
        goto retry;
    } else if (len < 0) {
        printf("Client termination: socket read returned with value -1");
        printf(" and errno = %s\n", strerror(errno));
    } else {
        printf("Client termination: socket read returned with value 0\n");
    }

    Close(connfd);
    return NULL;
}

static void *time_server(void* arg) {
    int connfd, n, maxfd;
    fd_set readfds;
    struct timeval timeout;
    time_t ticks;
    char strbuf[MAXLINE];
    int len;

    // Get connection socket fd
    connfd = *((int *) arg);
    free(arg);

    // Make this thread detachable
    Pthread_detach(pthread_self());

    maxfd = connfd + 1;
    FD_ZERO(&readfds);
    while (1) {
        FD_SET(connfd, &readfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        if ((n = select(maxfd, &readfds, NULL, NULL, &timeout)) < 0) {
            err_sys("Server termination: select error on connection socket");
        }

        if (n != 0) {
            if (errno != 0) {
                printf("Client terminated by errno = %s\n", strerror(errno));
            } else {
                printf("Client terminated Successfully\n");
            }
            break;
        }

        // Get current time and store in buffer
        ticks = time(NULL);
        snprintf(strbuf, sizeof(strbuf), "%.24s\r\n", ctime(&ticks));
        len = strlen(strbuf);

        if (write(connfd, strbuf, len) != len) {
            err_sys("Server termination: socket write error");
        }
    }

    Close(connfd);
    return NULL;
}

static int bind_and_listen(int portNo) {
    int listenfd, optVal;
    struct sockaddr_in servAddr;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err_sys("Server termination: server socket error");
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(portNo);

    // Set socket option -> SO_REUSEADDR
    optVal = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(optVal)) < 0) {
        err_sys("Server termination: setsockopt error");
    }

    if (bind(listenfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        err_sys("Server termination: server listen socket bind error");
    }

    if (listen(listenfd, LISTENQ) < 0) {
        err_sys("Server termination: sever socket listen error");
    }

    return listenfd;
}

static void spawn_child_service(int listenfd, void * (*pthread_func)(void *)) {
    struct sockaddr_in cliAddr;
    char strbuf[MAXLINE];
    pthread_t tid;
    socklen_t len;
    int *connfd;

    len = sizeof(cliAddr);
    connfd = (int *) malloc(sizeof(int));

    *connfd = Accept(listenfd, (SA *) &cliAddr, &len);

    printf("New Connection from %s, port %d\n",
            Inet_ntop(AF_INET, &cliAddr.sin_addr, strbuf, sizeof(strbuf)),
            ntohs(cliAddr.sin_port));
    // Spawn a new thread 
    Pthread_create(&tid, NULL, pthread_func, connfd);
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
            err_sys("Server termination: select error on echo and time listen sockets");
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
