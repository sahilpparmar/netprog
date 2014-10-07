#include "unp.h"
#include "common.h"

static int writefd = -1;
static void writeMsgAndExit(char *msg, int status) {
    char writeBuf[MAXLINE] = "\nEcho Client : ";
    strcat(strcat(writeBuf, msg), "\n");

    Write(writefd, writeBuf, strlen(writeBuf));
    exit(status);
}

static void sig_int(int signo) {
    writeMsgAndExit("Terminated Successfully", EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    char *hostAddr, *msg;
    char sendBuf[MAXLINE], recvBuf[MAXLINE];
    struct sockaddr_in servAddr;
    int sockfd, len;
    fd_set readfds;
    int maxfd;

    if (argc != 3) {
        writeMsgAndExit("Invalid Arguments", EXIT_FAILURE);
    }

    hostAddr = argv[1];
    writefd = atoi(argv[2]);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        writeMsgAndExit("socket error", EXIT_FAILURE);
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port   = htons(ECHO_PORT);

    if (inet_pton(AF_INET, hostAddr, &servAddr.sin_addr) <= 0) {
        writeMsgAndExit("inet_pton error", EXIT_FAILURE);
    }

    //TODO: Make socket non-blocking
    if (connect(sockfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        writeMsgAndExit("socket connect error", EXIT_FAILURE);
    }
    printf("Client succefully connected to server (%s)\n", hostAddr);

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        writeMsgAndExit("signal error", EXIT_FAILURE);
    }

    maxfd = sockfd + 1;
    FD_ZERO(&readfds);
    while (1) {
        FD_SET(fileno(stdin), &readfds);
        FD_SET(sockfd, &readfds);
        if (select(maxfd, &readfds, NULL, NULL, NULL) < 0) {
            writeMsgAndExit("select error on stdin and sockfd", EXIT_FAILURE);
        }

        if (FD_ISSET(fileno(stdin), &readfds)) {
            if (Fgets(sendBuf, MAXLINE, stdin) != NULL) {
                len = strlen(sendBuf);
                if (writen(sockfd, sendBuf, len) != len) {
                    writeMsgAndExit("writen error", EXIT_FAILURE);
                }
            } else {
                writeMsgAndExit("Terminated Successfully", EXIT_SUCCESS);
            }
        }
        if (FD_ISSET(sockfd, &readfds)) {
            if (Readline(sockfd, recvBuf, MAXLINE) > 0) {
                if (fputs(recvBuf, stdout) == EOF) {
                    writeMsgAndExit("fputs stdout error", EXIT_FAILURE);
                }
            } else {
                writeMsgAndExit("Server Crash", EXIT_FAILURE);
            }
        }
    }

    return 0;
}

