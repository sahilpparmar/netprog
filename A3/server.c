#include "common.h"

static char filePath[1024];

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

int main() {
    char buffer[1024], hostname[100];
    struct sockaddr_un serAddr;
    int sockfd;

    getFullPath(filePath, SER_FILE, sizeof(filePath), FALSE);
    sockfd = createAndBindUnixSocket(filePath);
    gethostname(hostname, strlen(hostname));

    Signal(SIGINT, sig_int);
    while (1) {
        char clientIP[100];
        int clientNode, clientPort;
        time_t ticks;

        msg_recv(sockfd, buffer, clientIP, &clientPort);

        // Get current time and store in buffer
        ticks = time(NULL);
        snprintf(buffer, sizeof(buffer), "%.24s", ctime(&ticks));
        
        printf("Server at node %s responding to request from %s\n", hostname, clientIP);
        msg_send(sockfd, clientIP, clientPort, buffer, FALSE);
    }

    Close(sockfd);
}

