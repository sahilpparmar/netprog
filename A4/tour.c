#include "tour.h"

static IP HostIP;

static void startTour(IP *IPList, int max) {
    printf("Initializing Tour\n");
}

static void startPassiveMode() {

}

int main(int argc, char* argv[]) {

    IP IPList[MAXHOPS] = {0};
    int nodeNo = 0;
    int i;

    getIPByVmNode(HostIP, getHostVmNodeNo());
    printf("Tour module running on VM%d with IP:%s\n", getHostVmNodeNo(), HostIP);

    if (argc == 1) {
        printf("No Tour specified\n");
        printf("Running in Listening Mode\n");
        startPassiveMode();

    } else {
        for (i = 1; i < argc; i++) {
            nodeNo = atoi(argv[i]+2);
            getIPByVmNode(IPList[i], nodeNo);
            printf("%d : VM%d ---> %s\n",i, nodeNo, IPList[i]);
        }
        memcpy((void *)IPList[0], (void *)HostIP, sizeof(HostIP));
        startTour(IPList, i);
    }
}
