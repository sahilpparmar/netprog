#include "unp.h"
#include "common.h"

static int writefd = -1;
static void writeMsgAndExit(char *msg, int status) {
    char writeBuf[MAXLINE] = "\nTime Client : ";
    strcat(strcat(writeBuf, msg), "\n");
    Write(writefd, writeBuf, strlen(writeBuf));
    exit(status);
}

static void sig_int(int signo) {
    writeMsgAndExit("Terminated Successfully", EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    char *hostAddr, *msg;
    char recvBuf[MAXLINE + 1];
    struct sockaddr_in servAddr;
    int sockfd, len;

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
    servAddr.sin_port   = htons(DAYTIME_PORT);

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

    while ((len = read(sockfd, recvBuf, MAXLINE)) > 0) {
        recvBuf[len] = 0;       /* null terminate */
        if (fputs(recvBuf, stdout) == EOF) {
            writeMsgAndExit("fputs stdout error", EXIT_FAILURE);
        }
    }
    if (len < 0) {
        writeMsgAndExit("socket read error", EXIT_FAILURE);
    }
    
    writeMsgAndExit("Server Crash", EXIT_FAILURE);
    return 0;
}

