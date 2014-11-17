#include "common.h"

static sigjmp_buf jmpToRetransmit;
static void sig_alarm(int signo) {
    siglongjmp(jmpToRetransmit, 1);
}

int main() {
    struct sockaddr_un cliAddr;
    char buffer[1024];
    int sockfd;

    sockfd = Socket(AF_LOCAL, SOCK_DGRAM, 0);

    bzero(&cliAddr, sizeof(cliAddr));
    cliAddr.sun_family = AF_LOCAL;
    strcpy(cliAddr.sun_path, getFullPath(buffer, CLI_FILE, sizeof(buffer), TRUE));

    Bind(sockfd, (SA*) &cliAddr, sizeof(cliAddr));

    Signal(SIGALRM, sig_alarm);

    while (1) {
        char serverIP[100];
        int serverNode, serverPort;
        bool forceRediscovery = FALSE;

        printf("Choose Server VM Node Number from VM1-VM10: ");
        if ((scanf("%d", &serverNode) != 1) || serverNode < 1 || serverNode > 10) {
            err_quit("\nInvalid Option! Exiting! Thank you!\n");
        }

jmpToRetransmit:
        msg_send(sockfd, canonicalIP[serverNode], SER_PORT, NULL, forceRediscovery);

        alarm(CLI_TIMEOUT);

        if (sigsetjmp(jmpToRetransmit, 1) != 0) {
            forceRediscovery = TRUE;
            goto jmpToRetransmit;
        }

        msg_recv(sockfd, buffer, serverIP, &serverPort);
    }
}

