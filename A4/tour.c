#include "tour.h"

static IP HostIP;

static void startTour(IP *IPList, int max) {
    printf("Initializing Tour\n");
}

static void startPassiveMode() {

}

static char* getHWAddrByIPAddr(IA s_ipaddr, char *s_haddr) {
    HWAddr hwAddr;
    struct sockaddr_in sockAddr;

    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr   = s_ipaddr;
    sockAddr.sin_port   = htons(0);

    bzero(&hwAddr, sizeof(hwAddr));
    hwAddr.sll_ifindex = 2;
    hwAddr.sll_hatype  = ARPHRD_ETHER;
    hwAddr.sll_halen   = ETH_ALEN;

    if (areq((SA *) &sockAddr, sizeof(sockAddr), &hwAddr) == 0) {
        memcpy(s_haddr, hwAddr.sll_addr, ETH_ALEN);
    }
    return s_haddr;
}

int main(int argc, char* argv[]) {

    IP IPList[MAXHOPS] = {0};
    int nodeNo = 0;
    int i;

    getIPStrByVmNode(HostIP, getHostVmNodeNo());
    printf("Tour module running on VM%d with IP:%s\n", getHostVmNodeNo(), HostIP);

    if (argc == 1) {
        printf("No Tour specified\n");
        printf("Running in Listening Mode\n");
        startPassiveMode();

    } else {
        for (i = 1; i < argc; i++) {
            nodeNo = atoi(argv[i]+2);
            getIPStrByVmNode(IPList[i], nodeNo);
            printf("%d : VM%d ---> %s\n", i, nodeNo, IPList[i]);
        }
        memcpy((void *)IPList[0], (void *)HostIP, sizeof(HostIP));
        startTour(IPList, argc);
    }
}

