#include "unp.h"
#define MSG_CLIENT_TERM "Client terminated successfully\n"
#define MSG_SERVER_CRASH "Client terminated due to Server crash\n"

int writefd;

void sig_int(int signo) {
    int len = strlen(MSG_CLIENT_TERM);
    if (write(writefd, MSG_CLIENT_TERM, len) != len) {
        err_sys("write error");
    }
    exit(0);
}

int main(int argc, char **argv) {
    char *hostAddr, *msg;
    char recvBuf[MAXLINE + 1];
    struct sockaddr_in servAddr;
    int sockfd, len;

    if (argc != 3) {
        err_quit("Invalid arguments");
    }

    hostAddr = argv[1];
    writefd = atoi(argv[2]);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err_sys("client socket error");
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    /* daytime server */
    servAddr.sin_port   = htons(13);

    if (inet_pton(AF_INET, hostAddr, &servAddr.sin_addr) <= 0) {
        err_quit("inet_pton error for %s", hostAddr);
    }

    //TODO: Make socket non-blocking
    if (connect(sockfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        err_sys("socket connect error");
    }
    printf("Client succefully connected to server (%s)\n", hostAddr);
    Signal(SIGINT, sig_int);

    while ((len = read(sockfd, recvBuf, MAXLINE)) > 0) {
        recvBuf[len] = 0;       /* null terminate */
        if (fputs(recvBuf, stdout) == EOF) {
            err_sys("fputs stdout error");
        }
    }
    if (len < 0) {
        err_sys("socket read error");
    }
    
    len = strlen(MSG_SERVER_CRASH);
    if (write(writefd, MSG_SERVER_CRASH, len) != len) {
        err_sys("write error");
    }
    
    return 0;
}

