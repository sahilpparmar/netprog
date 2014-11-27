#include <stdio.h>
#include "utils.h"
#include "tour.h"
IP HostIP;

void startTour(char* IP, int max) {

}

void startPassiveMode() {
}

int main(int argc, char* argv[]) {

    int nodeNo = 0;
    IP IPList[MAXHOPS] = {0};

    int i;

    getIPByVMNode(&HostIP, getHostVmNodeNo());
    printf("Tour module running on VM%d with IP:%s\n", getHostVMNodeNo(), HostIP);

    if(argc == 1) {
        printf("No Tour specified\n");
        printf("Running in Listening Mode\n");
        startPassiveMode();
        return;
    }
    else {
        for(i = 1; i < argc; i++) {
            nodeNo = atoi(argv[i]+2);
            getIPByVmNode(IPList[i], nodeNo);
            printf("%d : VM%d ---> %s\n",i, nodeNo, IPList[i]);
        }
        memcpy(IPList[0], HostIP, sizeof(HostIP));
        startTour(&IPList, i);
    }
}
