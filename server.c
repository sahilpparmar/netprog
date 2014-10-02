#include "unp.h"
#include<time.h>

static void *time_server(void* arg) {
    int connfd, n, maxfd;
    fd_set readfds;
    struct timeval timeout;
    time_t ticks;
    char strbuf[MAXLINE];
    socklen_t len;

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
            err_sys("select error on connection socket");
        }

        if (n != 0) {
            //TODO: check errno before terminating
            printf("client termination!\n");
            break;
        }

        // Get current time and store in buffer
        ticks = time(NULL);
        snprintf(strbuf, sizeof(strbuf), "%.24s\r\n", ctime(&ticks));
        len = strlen(strbuf);

        if (write(connfd, strbuf, len) != len) {
            err_sys("socket write error");
        }
    }

    if (close(connfd) == -1) {
        err_sys("connection close error");
    }
    
    return NULL;
}

int main() {
    int listenfd, *connfd;
    struct sockaddr_in servAddr, cliAddr;
    pthread_t tid;
    char strbuf[MAXLINE];
    socklen_t len;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err_sys("server socket error");
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(13);   /* daytime server */

    if (bind(listenfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        err_sys("server listen socket bind error");
    }

    // TODO: set backlog
    if (listen(listenfd, 0) < 0) {
        err_sys("sever socket listen error");
    }

    while(1) {
        len = sizeof(cliAddr);
        connfd = (int *) malloc(sizeof(int));

        if ((*connfd = accept(listenfd, (SA *) &cliAddr, &len)) < 0) {
            // TODO:
            //if (errno == EPROTO || errno == ECONNABORTED)
            err_sys("connection accept error");
        }

        printf("New Connection from %s, port %d\n",
                Inet_ntop(AF_INET, &cliAddr.sin_addr, strbuf, sizeof(strbuf)),
                ntohs(cliAddr.sin_port));
        // Spawn a detachable thread 
        Pthread_create(&tid, NULL, &time_server, connfd);
    }

    return 0;
}
