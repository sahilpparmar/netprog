#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "errno.h"
#include "hw_addrs.h"
#include "common.h"
#include "odr.h"

static char filePath[1024], hostNode, hostIP[100];

static void sig_int(int signo) {
    unlink(filePath);
    exit(0);
}

void printInterface(struct hwa_info *hwa) {
    struct sockaddr	*sa;
    char   *ptr;
    int    i, prflag;

    printf("%s :%s", hwa->if_name, ((hwa->ip_alias) == IP_ALIAS) ? " (alias)\n" : "\n");

    if ( (sa = hwa->ip_addr) != NULL)
        printf("         IP addr = %s\n", Sock_ntop_host(sa, sizeof(*sa)));

    prflag = 0;
    i = 0;
    do {
        if (hwa->if_haddr[i] != '\0') {
            prflag = 1;
            break;
        }
    } while (++i < IF_HADDR);

    if (prflag) {
        printf("         HW addr = ");
        ptr = hwa->if_haddr;
        i = IF_HADDR;
        do {
            printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
        } while (--i > 0);
    }

    printf("\n         interface index = %d\n\n", hwa->if_index);

}
void printPacket(ethernetFrame *etherFrame,uint32_t length) {

    int i;
    ODRPacket *packet = &(etherFrame->packet);

    printf ("\nEthernet frame header:\n");

    printf ("Destination MAC (this node): ");
    for (i=0; i<=5; i++) {
        printf ("%02x:", etherFrame->destMAC[i]);
    }
    printf ("\n");

    printf ("Source MAC: ");
    for (i=0; i<=5; i++) {
        printf ("%02x:", etherFrame->sourceMAC[i]);
    } 
    printf("\n");

    printf("Ethernet Type Code: %u \n", (((etherFrame->protocol[0]) <<8 ) + etherFrame->protocol[1] ));

    printf ("\nODR packet header:\n");
    printf("Packet Type: %u", packet->type);
    printf("Source IP: %s   Port no: %u \n", packet->sourceIP, packet->sourcePort);
    printf("Destination IP: %s   Port no: %u \n", packet->destIP, packet->destPort);
    printf("Hop count: %u \n", packet->hopCount);
    printf("Broadcast ID: %u \n", packet->broadID);

    if (packet->Asent)
        printf("Asent: True\n");
    else
        printf("Asent: False\n");

    if (packet->forceRedisc)
        printf("forceRedisc: True\n");
    else
        printf("forceRedisc: False\n");

        printf("Data: %s \n", packet->data);

    return;
}
/*
// Function that would check and clear up waiting packets in the buffer
int sendWaitingPackets(int destIndex, routingTable *routes, int socket) {
    waitingFrame *waitingFrame;
        waitingFrame = (routes[destIndex]).waitListHead;
        while (waitingFrame != NULL) {
            waitingFrame = waitingFrame->next;
        }
        (routes[destIndex]).waitListHead = NULL;
}

bool createUpdateRouteEntry(ethernetFrame *frame, int destIndex, int inIface, routingTable *routes, int inSocket) {
    ODRPacket *packet = &(frame->packet);

    routingTable *routeEntry = &(*routes[destIndex]);
    if(routeEntry->isValid == False                     // New Entry
            || routeEntry->hopCount >= packet->hopCount // Better Route
            || routeEntry->timeStamp-STALENESS < 0      // Route expired
            || routeEntry->broadID > packet->broadID) { // Newer Broadcast ID
        
        routeEntry->isValid = True;
        routeEntry->broadID = packet->broadID;
        routeEntry->ifaceNum = inIface;
        routeEntry->nextHopMAC = frame->sourceMAC;
        routeEntry->hopCount = packet->hopCount;

        sendWaitingPackets(destIndex, routes, inSocket);

        routeEntry->timeStamp = (uint32_t) time (NULL); 
        return True;
    }

    return False;
}
int floodPacket(ODRPacket *packet, ifaceInfo *ifaceList, int exceptInterface, int totalSockets) {

    int retVal;
    int index;

    uint8_t broadMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    ethernetFrame frame;
    memcpy(&(frame.destMAC), broadMAC, sizeof(broadMAC));
    memcpy(&(frame.protocol), PROTOCOL_NUMBER, sizeof(PROTOCOL_NUMBER));
    memcpy(&(frame.packet), packet, sizeof(ODRPacket));

    for(index = 0; index < totalSockets; index++) {

        if (index != exceptInterface) {
            memcpy(&(frame.sourceMAC), (ifaceList[index]).ifaceMAC);
            send_result = sendto((ifaceList[index]).ifaceSocket, (void *) &frame, sizeof(ethernetFrame), 0, (struct sockaddr *)&)
        }

    }
    send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, 
                      (struct sockaddr*)&socket_address, sizeof(socket_address));
    if (send_result == -1) {
        pr
    }

}

int  sendonInterface(int index, int nextHop, uint8_t nextHopMAC[], uint32_t hopCount, routingTable *routes, int* sockets ) {
}
*/

/*
int handleRREQ(ODRPacket *packet, ifaceInfo *ifaceList, int* sockets, int incomingInter, int totalSockets,int sourceIndex ) {
    // Return 0 - Nothing needs to be done: New entry - Send RREQs
    // Return 1 - Have the entry, so sending RREP to the requestor as well as send RREQs on other interfaces with blah
    // Check if entry is present
    if ( (routes[sourceIndex].nextHop == 0) // No entry in the routing table 
            || (routes[sourceIndex].timestamp - STALENESS <= 0 ) // Route has been expired
            || (routes[sourceIndex]. hopCount >= packet->hopCount) ) {// If its a better route
        createRouteEntry(sourceIndex, incomingInterf, nextHopMAC, packet->hopCount, routes );
        createUpdateRouteEntry(ethernetFrame *frame, int destIndex, int incomingInter, routingTable *routes,int inSocket); 


    }

    
    // Logic for flooding RREPS, or replying with RREQs
}
*/
void processFrame(ethernetFrame *etherFrame, routingTable *routes, ifaceInfo *ifaceList, int inSockIndex, int totalSockets) {
    
    uint32_t  sourceIndex, destIndex;
    ODRPacket *packet;
    int retval = -1;

    packet = &(etherFrame->packet);

    switch(packet->type){
    
        case RREQ: // RREQ packet
            printf("RREQ packet received!\n");
//            sourceIndex = getSourceIndex(packet->sourceIP);
            //handleRREQ(packet, routes, ifaceList, inSockIndex, totalSockets);
            break;
   
        case RREP: // RREP packet
            printf("RREP packet received!\n");
            break;
     
        case DATA: // Data packet
            printf("Data packet received!\n");
            break;
    
    
        default: // Error
            printf("Malformed packet received!\n");
    } // Switch

}
int readAllSockets(int unixSockFd, ifaceInfo *ifaceList, int totalIfaceSock, fd_set fdSet, routingTable* routes) {
    int maxfd, index;
    int length = 0; /*length of the received frame*/ 
    ethernetFrame etherFrame; /*Buffer for ethernet frame*/
    fd_set readFdSet;

    maxfd = ifaceList[totalIfaceSock - 1].ifaceSocket + 1;

    while (1) {
        readFdSet = fdSet;
        Select(maxfd, &readFdSet, NULL, NULL, NULL);

        // Check if got a packet on an unix domain socket
        if (FD_ISSET(unixSockFd, &readFdSet)) {
            printf("Unix Socket Received\n");
            Recvfrom(unixSockFd, &etherFrame, sizeof(etherFrame), 0, NULL, NULL);
             
        }

        // Check if got a packet on an iface socket
        for (index = 0; index < totalIfaceSock; index++) {
            if (FD_ISSET(ifaceList[index].ifaceSocket, &readFdSet)) {
                length = Recvfrom(ifaceList[index].ifaceSocket, &etherFrame, sizeof(etherFrame), 0, NULL, NULL);

                if (length < 0) {
                    printf("Error in receiving packet");
                }

                // Print out contents of received ethernet frame
                printPacket(&etherFrame, length);

                // Process frame
                processFrame(&etherFrame, routes, ifaceList, index, totalIfaceSock);
            }
        }
    }
}

int createIfaceSockets(ifaceInfo *ifaceSockList, int *totalIfaceSock, fd_set *fdSet) {
    struct hwa_info *hwa, *hwahead;
    int startInterface = 2; //TODO All interfaces apart from lo and eth0
    int index = 0;
    int totalInterfaces = 0;
    struct sockaddr_ll listenFilter;

    printf("\n");

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next, totalInterfaces++);
    printf ("Total Number of Interfaces: %d\n", totalInterfaces);

    totalInterfaces = totalInterfaces - 2;  // Discarding eth0 and lo
    *totalIfaceSock = totalInterfaces;      // setting variables from the main function

    ifaceSockList = Malloc(totalInterfaces * sizeof(ifaceInfo));

    bzero(&listenFilter, sizeof(listenFilter));
    listenFilter.sll_protocol = PROTOCOL_NUMBER;

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
        printInterface(hwa);

        if (hwa->if_index > startInterface) {
            // if the interface number is greater than 2 then make sockets on each interfaces
            if (((ifaceSockList[index]).ifaceSocket = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER))) < 0) {
                err_quit("Error in creating PF_PACKET socket for interface: %d", index + 3);
            }

            memcpy((ifaceSockList[index]).ifaceMAC,hwa->if_haddr, 6); // MAC = 6
            FD_SET(ifaceSockList[index].ifaceSocket, fdSet);
            listenFilter.sll_ifindex = hwa->if_index;
            //TODO: Bind error
            //Bind(ifaceSockList[index].ifaceSocket, (struct sockaddr *) &listenFilter, sizeof(listenFilter));
            index++;
        }
    }

    free_hwa_info(hwahead);
    return;
}


int main()
{
    routingTable routes[TOTAL_NODES + 1];
    ifaceInfo *ifaceSockList;
    int totalIfaceSock, unixSockFd;
    fd_set fdSet;

    Signal(SIGINT, sig_int);
    hostNode = getHostVmNodeNo();
    FD_ZERO(&fdSet);

    // Create Unix domain socket
    getFullPath(filePath, ODR_FILE, sizeof(filePath), FALSE);
    unixSockFd = createAndBindUnixSocket(filePath);
    FD_SET(unixSockFd, &fdSet);


    // Create interface sockets
    createIfaceSockets(ifaceSockList, &totalIfaceSock, &fdSet);

    // Read incoming packets on all sockets
    readAllSockets(unixSockFd, ifaceSockList, totalIfaceSock, fdSet, routes);

    free(ifaceSockList);

    unlink(filePath);
    Close(unixSockFd);
}

