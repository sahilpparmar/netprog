#include "common.h"

static char filePath[1024], hostNode, hostIP[100];

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

int main() {
    char buffer[1024];
    struct sockaddr_un serAddr;
    int sockfd;

    getFullPath(filePath, SER_FILE, sizeof(filePath), FALSE);
    sockfd = createAndBindUnixSocket(filePath);
    hostNode = getHostVmNodeNo();
    getIPByVmNode(hostIP, hostNode);
    printf("Server running on VM%d (%s)\n", hostNode, hostIP);

    Signal(SIGINT, sig_int);
    while (1) {
        char clientIP[100];
        int clientPort;
        time_t ticks;

        msg_recv(sockfd, buffer, clientIP, &clientPort);

        // Get current time and store in buffer
        ticks = time(NULL);
        snprintf(buffer, sizeof(buffer), "%.24s", ctime(&ticks));
        
        printf("Server at node VM%d: responding to request from VM%d\n", hostNode, getVmNodeByIP(clientIP));
        msg_send(sockfd, clientIP, clientPort, buffer, FALSE);
    }

    Close(sockfd);
}

