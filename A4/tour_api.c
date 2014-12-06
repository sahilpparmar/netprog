#include "tour.h"
#include "api.h"

static int createAndConnectUnixSocket() {
    struct sockaddr_un servAddr;
    char filePath[1024];
    int sockfd;

    sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sun_family = AF_LOCAL;
    getFullPath(filePath, ARP_FILE, sizeof(filePath), FALSE);
    strcpy(servAddr.sun_path, filePath);

    if (connect(sockfd, (SA *) &servAddr, sizeof(servAddr)) < 0) {
        return -1;
    }

    return sockfd;
}

static void writeUnixSocket(int sockfd, IA destIPAddr, int ifindex,
                            uint16_t hatype, uint8_t halen)
{
    SendToARP writeData;
    writeData.ipaddr.s_addr = destIPAddr.s_addr;
    writeData.ifindex       = ifindex;
    writeData.hatype        = hatype;
    writeData.halen         = halen;
    Writen(sockfd, &writeData, sizeof(writeData));
}

static void readUnixSocket(int sockfd, char *hwaddr) {
    ReceiveFromARP readData;
    Read(sockfd, &readData, sizeof(readData));
    memcpy(hwaddr, &readData, IF_HADDR);
}

int areq(SA *IPaddr, socklen_t salen, HWAddr *hwaddr) {
    int sockfd;
    fd_set readfds;
    struct timeval timeout;

    if ((sockfd = createAndConnectUnixSocket()) == -1) {
        err_msg("Unable to connect to ARP Unix Domain Socket");
        return -1;
    }

    // Send AREQ to ARP module
    printf("AREQ Request for IP: %s sent\n", getIPStrByIPAddr(((struct sockaddr_in*) IPaddr)->sin_addr));
    writeUnixSocket(sockfd, ((struct sockaddr_in*) IPaddr)->sin_addr,
            hwaddr->sll_ifindex, hwaddr->sll_hatype, hwaddr->sll_halen);

    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
    timeout.tv_sec = AREQ_TIMEOUT;
    timeout.tv_usec = 0;

    if (Select(sockfd + 1, &readfds, NULL, NULL, &timeout) == 0) {
        // AREQ timeout
        close(sockfd);
        err_msg("AREQ Reply Timeout: Unable to fetch HW Address");
        return -1;
    }
    
    // Receive ARP response
    readUnixSocket(sockfd, hwaddr->sll_addr);
    printf("AREQ Reply Success => HW Address: %s\n", ethAddrNtoP(hwaddr->sll_addr));

    close(sockfd);
    return 0;
}

