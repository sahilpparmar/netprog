#include "unp.h"

static int writefd = -1;
static void writeMsgAndExit(char *msg, int status) {
    char writeBuf[MAXLINE] = "\nEcho Client : ";
    strcat(strcat(writeBuf, msg), "\n");

    Write(writefd, writeBuf, strlen(writeBuf));
    exit(status);
}

static void sig_int(int signo) {
    writeMsgAndExit("Terminated Successfully", 0);
}

int main(int argc, char **argv) {
    char *hostAddr, *msg;
    char sendBuf[MAXLINE], recvBuf[MAXLINE];
    struct sockaddr_in servAddr;
    int sockfd, len;
    fd_set readfds;
    int maxfd;

    if (argc != 3) {
        writeMsgAndExit("Invalid Arguments", -1);
    }

    hostAddr = argv[1];
    writefd = atoi(argv[2]);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        writeMsgAndExit("socket error", -1);
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port   = htons(SERV_PORT);

    if (inet_pton(AF_INET, hostAddr, &servAddr.sin_addr) <= 0) {
        writeMsgAndExit("inet_pton error", -1);
    }

    //TODO: Make socket non-blocking
    if (connect(sockfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        writeMsgAndExit("socket connect error", -1);
    }
    printf("Client succefully connected to server (%s)\n", hostAddr);

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        writeMsgAndExit("signal error", -1);
    }

    maxfd = sockfd + 1;
    FD_ZERO(&readfds);
    while (1) {
        FD_SET(fileno(stdin), &readfds);
        FD_SET(sockfd, &readfds);
        if (select(maxfd, &readfds, NULL, NULL, NULL) < 0) {
            writeMsgAndExit("select error on stdin and sockfd", -1);
        }

        if (FD_ISSET(fileno(stdin), &readfds)) {
            if (Fgets(sendBuf, MAXLINE, stdin) != NULL) {
                len = strlen(sendBuf);
                if (writen(sockfd, sendBuf, len) != len) {
                    writeMsgAndExit("writen error", -1);
                }
            } else {
                writeMsgAndExit("Terminated Successfully", 0);
            }
        }
        if (FD_ISSET(sockfd, &readfds)) {
            if (Readline(sockfd, recvBuf, MAXLINE) > 0) {
                if (fputs(recvBuf, stdout) == EOF) {
                    writeMsgAndExit("fputs stdout error", -1);
                }
            } else {
                writeMsgAndExit("Server Crash", -1);
            }
        }
    }

    return 0;
}

