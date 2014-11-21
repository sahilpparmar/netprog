#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include "common.h"
#include "hw_addrs.h"
#include "odr.h"

char filePath[1024], hostNode, hostIP[100];

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
void printPacket(EthernetFrame *etherFrame,uint32_t length) {

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

int sendonIFace(ODRPacket *packet, uint8_t srcMAC[6], uint8_t destMAC[6], uint16_t outIfaceNum, int socket) {

    int retVal;
    uint16_t protocol = PROTOCOL_NUMBER;

    /*target address*/
    struct sockaddr_ll socketAddress;
    EthernetFrame frame;

    /*RAW communication*/
    socketAddress.sll_family   = PF_PACKET;    
    socketAddress.sll_protocol = htons(PROTOCOL_NUMBER);  

    /*ARP hardware identifier is ethernet*/
    socketAddress.sll_hatype   = ARPHRD_ETHER;

    /*target is another host*/
    socketAddress.sll_pkttype  = PACKET_OTHERHOST;

    /*address length*/
    socketAddress.sll_halen    = ETH_ALEN;

    memcpy(&(socketAddress.sll_addr), destMAC, sizeof(destMAC));

    memcpy(&(frame.destMAC), destMAC, sizeof(destMAC));

    memcpy(&(frame.protocol), (void *)&protocol, sizeof(frame.protocol));
    memcpy(&(frame.packet), packet, sizeof(ODRPacket));

    memcpy(&(frame.sourceMAC), srcMAC, sizeof(srcMAC));
    socketAddress.sll_ifindex  = outIfaceNum;

    // Increment Hop count in the packet
    packet->hopCount = (packet->hopCount) + 1;

    retVal = sendto(socket, (void *) &frame, sizeof(EthernetFrame), 
            0, (struct sockaddr *)&socketAddress, sizeof(socketAddress));
    if (retVal == -1) {
        perror("Error in Sending packet");
    }
    return;
}

// Function that would check and clear up waiting packets in the buffer
int sendWaitingPackets(int destIndex, RoutingTable *routes, IfaceInfo *ifaceList) {

    uint8_t srcMAC[6], dstMAC[6];
    uint16_t outIfaceNum;
    int outSocket;
    int packetSent = 0;
    WaitingPacket *waitingPackets;
    WaitingPacket *freePacket;

    outIfaceNum = routes[destIndex].ifaceNum;
    outSocket = ifaceList[outIfaceNum+2].ifaceSocket;
    //assert that route bool is true

    waitingPackets = routes[destIndex].waitListHead;
    freePacket = routes[destIndex].waitListHead;
    memcpy(dstMAC, routes[destIndex].nextHopMAC, sizeof(dstMAC));
    memcpy(srcMAC, ifaceList[outIfaceNum + 2/*lo and eth0*/].ifaceMAC, sizeof(srcMAC));


    while (waitingPackets != NULL) {

        sendonIFace(&(waitingPackets->packet), srcMAC, dstMAC, outIfaceNum,outSocket);
        waitingPackets = waitingPackets->next;
        packetSent++;

        free(freePacket);
        freePacket = waitingPackets;

    }
    routes[destIndex].waitListHead = NULL;

    return packetSent;
}

char *printMAC(char * MAC, char* TempMAC) {
    int i;
    for(i = 0; i <6; i++) {
        *TempMAC++ = *MAC++;
        if (i % 2 == 0 && i != 0)
            *TempMAC = ':';
    }
    *TempMAC = '\0';
    return TempMAC;
}
void printTable(RoutingTable *routes, int specific) {
    int i = 0;
    char MACTemp[10];
    printf("===================================================================================================================================\n");
    printf("Destination Node |   isValid  |     broadID     |   ifaceNum |           nextHopMAC       | hopCount |  timestamp  | waitListHead |\n");
    printf("===================================================================================================================================\n");

    if (specific != 0) {
        printf(" VM %10d \t | %10d | %10d\t| %10d | %15s\t\t  |%10d| %10u  | %12p |\n",
                specific,   routes[specific].isValid, routes[specific].broadID, routes[specific].ifaceNum,
                printMAC(routes[specific].nextHopMAC, MACTemp), routes[specific].hopCount, routes[specific].timeStamp, routes[specific].waitListHead);
    }
    else {
        for(i=1; i< (TOTAL_VMS + 1); i++) {
            printf(" VM %10d \t | %10d | %10d\t| %10d | %15s\t\t  |%10d| %10u  | %12p |\n",
                    i,   routes[i].isValid, routes[i].broadID, routes[i].ifaceNum,
                    printMAC(routes[i].nextHopMAC, MACTemp), routes[i].hopCount, routes[i].timeStamp, routes[i].waitListHead);
        }
    }
    printf("===================================================================================================================================\n");

}


bool createUpdateRouteEntry(EthernetFrame *frame, int inIface, RoutingTable *routes, IfaceInfo *ifaceList) {
    int destNode;

    ODRPacket *packet = &(frame->packet);
    destNode = getVmNodeByIP(packet->destIP);  

    RoutingTable *routeEntry = &routes[destNode];
    if( (routeEntry->isValid == FALSE                                           // New Entry
                || routeEntry->hopCount >= packet->hopCount                     // Better Route
                || routeEntry->timeStamp-STALENESS < 0)) {                      // Route expired
        if (packet-> broadID == 0 || routeEntry->broadID > packet->broadID) {   // Newer Broadcast ID / RREPs have broadcastID 0

            routeEntry->isValid = TRUE;
            routeEntry->broadID = packet->broadID;
            routeEntry->ifaceNum = inIface;
            memcpy(routeEntry->nextHopMAC, frame->sourceMAC, sizeof(frame->sourceMAC));
            routeEntry->hopCount = packet->hopCount;

            printf("Cleared Waiting Queue for dest Node: VM%d, Packets Sent: %d\n", destNode, sendWaitingPackets(destNode, routes, ifaceList));

            routeEntry->timeStamp = (uint32_t) time (NULL); 
            return TRUE;
        }
    }

    return FALSE;
}

int fillODRPacket(ODRPacket *packet, packetType type, char *srcIP, char *dstIP, uint32_t srcPort, uint32_t dstPort, int hopCount, int broadID, bool Asent, bool forceRedisc, char* data, int length) {
    packet->type = type;
    memcpy(&(packet->sourceIP), srcIP, IPLEN);
    memcpy(&(packet->destIP), dstIP, IPLEN);
    packet->sourcePort = srcPort;
    packet->destPort = dstPort;
    packet->hopCount = hopCount;
    packet->broadID = broadID;
    packet->Asent = Asent;
    packet->forceRedisc = forceRedisc;
    memcpy(&(packet->data), data, length);

    return 1;
}

void addToWaitList(ODRPacket *packet, RoutingTable *routes,int destNode) {

    WaitingPacket *newPacket = Malloc(sizeof(WaitingPacket));

    memcpy(&(newPacket->packet), packet, sizeof(ODRPacket));
    newPacket->next = routes[destNode].waitListHead;

    routes[destNode].waitListHead = newPacket;

    return;
}
bool isRoutePresent(ODRPacket *packet, RoutingTable *routes) {
    int destNode;

    destNode = getVmNodeByIP(packet->destIP);  

    RoutingTable *routeEntry = &(routes[destNode]);
    if( (routeEntry->isValid == FALSE                     // InValid Route Entry
                || routeEntry->timeStamp-STALENESS < 0)) {      // Route expired

        routeEntry->isValid = FALSE;
        addToWaitList(packet, routes, destNode);
        return FALSE;
    }

    return TRUE;
}


void floodPacket(ODRPacket *packet, IfaceInfo *ifaceList, int exceptInterface, int totalSockets) {

    int retVal;
    int index;
    uint8_t broadMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint16_t protocol = PROTOCOL_NUMBER;

    /*target address*/
    struct sockaddr_ll socketAddress;
    EthernetFrame frame;

    /*RAW communication*/
    socketAddress.sll_family   = PF_PACKET;    
    socketAddress.sll_protocol = htons(PROTOCOL_NUMBER);  

    /*ARP hardware identifier is ethernet*/
    socketAddress.sll_hatype   = ARPHRD_ETHER;

    /*target is another host*/
    socketAddress.sll_pkttype  = PACKET_OTHERHOST;

    /*address length*/
    socketAddress.sll_halen    = ETH_ALEN;
    memcpy(&(socketAddress.sll_addr),broadMAC, sizeof(broadMAC));

    memcpy(&(frame.destMAC), broadMAC, sizeof(broadMAC));

    memcpy(&(frame.protocol), (void *)&protocol, sizeof(frame.protocol));
    memcpy(&(frame.packet), packet, sizeof(ODRPacket));

    // Increment Hop count in the packet
    packet->hopCount = (packet->hopCount) + 1;

    for(index = 0; index < totalSockets; index++) {

        if (index != exceptInterface) {

            memcpy(&(frame.sourceMAC), (ifaceList[index]).ifaceMAC, sizeof(frame.sourceMAC));
            socketAddress.sll_ifindex  = ifaceList[index].ifaceNum;

            retVal = sendto((ifaceList[index]).ifaceSocket, (void *) &frame, sizeof(EthernetFrame), 
                    0, (struct sockaddr *)&socketAddress, sizeof(socketAddress));
            if (retVal == -1) {
                perror("Error in Flooding packet");
            }
        }
    }
    return;
}

//TODO Check if I am the destination node
bool CheckIfDestNode(packet) {
    return TRUE;
}

void changePacketType(ODRPacket *packet, packetType type) {
    packet->type = type;
}

void incHopCount(ODRPacket *packet) {
    packet->hopCount = packet->hopCount + 1;
    return;
}

void setAsentFlag(ODRPacket *packet) {
    packet->Asent = TRUE;
    return;
}

int handleRREQ(EthernetFrame *etherFrame, RoutingTable *routes, IfaceInfo *ifaceList, int inSockIndex, int totalSockets) {

    uint32_t  destIndex;
    ODRPacket *packet;
    int retval = -1;
    int nwdestNode;
    int nwsrcNode;
    bool cond1, cond2;

    packet = Malloc(sizeof(ODRPacket));

    memcpy(packet, &(etherFrame->packet), sizeof(ODRPacket));

    cond1 = createUpdateRouteEntry(etherFrame, inSockIndex, routes, ifaceList);
    if (CheckIfDestNode(packet) && !packet->Asent) {
        // Create RREPs and send them back
        ODRPacket RREPPacket;
        nwdestNode = getVmNodeByIP(packet->sourceIP);  

        fillODRPacket(&RREPPacket, RREP, packet->destIP, packet->sourceIP,
                packet->destPort, packet->sourcePort, 0, 0, FALSE, 
                packet->forceRedisc/*TODO Check */,NULL, 0);

        sendonIFace(packet, ifaceList[inSockIndex].ifaceMAC, routes[nwdestNode].nextHopMAC,
                ifaceList[inSockIndex].ifaceNum,
                ifaceList[inSockIndex].ifaceSocket); 

    }

    if(isRoutePresent(packet, routes)) { // Send RREP to source
        // Create RREPs and send them back
        ODRPacket RREPPacket;
        nwdestNode = getVmNodeByIP(packet->sourceIP); 
        nwsrcNode = getVmNodeByIP(packet->destIP);//TODO 

        fillODRPacket(&RREPPacket, RREP, packet->destIP/*TODO Change it to MyIP and port number*/, packet->sourceIP,
                packet->destPort, packet->sourcePort, 
                routes[getVmNodeByIP(packet->destIP)].hopCount + 1/*HopCount*/,
                0, FALSE, 
                packet->forceRedisc/*TODO Check */,NULL, 0);

        sendonIFace(packet, ifaceList[inSockIndex].ifaceMAC, routes[nwdestNode].nextHopMAC,
                ifaceList[inSockIndex].ifaceNum,
                ifaceList[inSockIndex].ifaceSocket); 

        if (cond1) { 
            // Route entry updated so send Flood RREQs with Asent flag 
            ODRPacket RREQPacket;
            memcpy(&RREQPacket, packet, sizeof(RREQPacket));
            incHopCount(&RREQPacket);
            setAsentFlag(&RREQPacket);
            floodPacket(&RREQPacket, ifaceList, inSockIndex, totalSockets);
        }

    }
    else { // Route not present So keep flooding the Packet
        incHopCount(packet);
        floodPacket(packet, ifaceList, inSockIndex, totalSockets);
    }
}

void processFrame(EthernetFrame *etherFrame, RoutingTable *routes, IfaceInfo *ifaceList, int inSockIndex, int totalSockets) {

    ODRPacket *packet;
    packet = &(etherFrame->packet);


    switch(packet->type){

        case RREQ: // RREQ packet
            printf("RREQ packet received!\n");
            handleRREQ(etherFrame, routes, ifaceList, inSockIndex, totalSockets);
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

int startCommunication(EthernetFrame *etherFrame, RoutingTable *routes, IfaceInfo *ifaceList, int totalSockets) {

    uint8_t srcMAC[6], dstMAC[6];
    int destIndex, outIfaceNum, outSocket;
    ODRPacket *packet;


    packet = Malloc(sizeof(ODRPacket));
    memcpy(&packet, &(etherFrame->packet), sizeof(ODRPacket));
    changePacketType(packet, DATA);

    if(isRoutePresent(packet, routes)){
        printf("Route is present\n");
        destIndex = getVmNodeByIP(packet->destIP);
        outIfaceNum = routes[destIndex].ifaceNum;
        outSocket = ifaceList[outIfaceNum+2].ifaceSocket;

        memcpy(dstMAC, routes[destIndex].nextHopMAC, sizeof(dstMAC));
        memcpy(srcMAC, ifaceList[outIfaceNum + 2/*lo and eth0*/].ifaceMAC, sizeof(srcMAC));

        sendonIFace(packet, srcMAC, dstMAC, outIfaceNum, outSocket);
        return 0;
    }
    else{
        // Create RREQ and Flood it out
        printf("Route is not present, generating RREQ\n");
        ODRPacket RREQPacket;
        fillODRPacket(&RREQPacket, RREQ, packet->destIP, packet->sourceIP,
                packet->destPort, packet->sourcePort, 0, 0, FALSE, 
                packet->forceRedisc/*TODO Check */,NULL, 0);

        floodPacket(&RREQPacket, ifaceList, -1 /* Flood on all interfaces */, totalSockets);
        return 1;

    }
}

int readAllSockets(int unixSockFd, IfaceInfo *ifaceList, int totalIfaceSock, fd_set fdSet, RoutingTable* routes) {
    int maxfd, index;
    int length = 0; /*length of the received frame*/ 
    EthernetFrame etherFrame; /*Buffer for ethernet frame*/
    fd_set readFdSet;

    maxfd = ifaceList[totalIfaceSock - 1].ifaceSocket + 1;
    printf("\nReading all incoming packets =>\n");

    while (1) {
        readFdSet = fdSet;
        Select(maxfd, &readFdSet, NULL, NULL, NULL);

        // Check if got a packet on an unix domain socket
        if (FD_ISSET(unixSockFd, &readFdSet)) {
            if(processUnixPacket(unixSockFd)) 
                startCommunication(&etherFrame, routes, ifaceList, totalIfaceSock);
        } else {

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
}

int createIfaceSockets(IfaceInfo **ifaceSockList, fd_set *fdSet) {
    struct hwa_info *hwa, *hwahead;
    int totalInterfaces = 0, index = 0;
    struct sockaddr_ll listenFilter;

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next, totalInterfaces++);
    printf("\nFollowing are %d HW Interfaces =>\n", totalInterfaces);

    *ifaceSockList = Malloc(totalInterfaces * sizeof(IfaceInfo));

    bzero(&listenFilter, sizeof(listenFilter));

    /*RAW communication*/
    listenFilter.sll_family   = PF_PACKET;    
    listenFilter.sll_protocol = htons(PROTOCOL_NUMBER);  

    /*ARP hardware identifier is ethernet*/
    listenFilter.sll_hatype   = ARPHRD_ETHER;

    /*target is another host*/
    listenFilter.sll_pkttype  = PACKET_OTHERHOST;

    /*address length*/
    listenFilter.sll_halen    = ETH_ALEN;

    for (hwa = hwahead; hwa != NULL; hwa = hwa->hwa_next) {
        printInterface(hwa);

        if ((strcmp(hwa->if_name, "lo") != 0) && (strcmp(hwa->if_name, "eth0") != 0)) {
            // if the interface number is greater than 2 then make sockets on each interfaces
            if ((((*ifaceSockList)[index]).ifaceSocket = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER))) < 0) {
                err_quit("Error in creating PF_PACKET socket for interface: %d", index + 3);
            }

            memcpy(((*ifaceSockList)[index]).ifaceMAC, hwa->if_haddr, 6); // MAC = 6
            FD_SET((*ifaceSockList)[index].ifaceSocket, fdSet);
            listenFilter.sll_ifindex = hwa->if_index;
            Bind((*ifaceSockList)[index].ifaceSocket, (struct sockaddr *) &listenFilter, sizeof(listenFilter));
            index++;
        }
    }
    free_hwa_info(hwahead);

    printf("%d interfaces Bind\n", index);
    return index;
}


int main() {
    RoutingTable routes[TOTAL_VMS + 1] = {0};
    IfaceInfo *ifaceSockList;
    int totalIfaceSock, unixSockFd, filePortMapCnt;
    fd_set fdSet;

    printTable(routes, 0);
    hostNode = getHostVmNodeNo();
    getIPByVmNode(hostIP, hostNode);
    printf("ODR running on VM%d (%s)\n", hostNode, hostIP);

    Signal(SIGINT, sig_int);
    FD_ZERO(&fdSet);
    
    // Initialize filePath to Port Number Map
    initFilePortMap();

    // Create Unix domain socket
    //    getFullPath(filePath, ODR_FILE, sizeof(filePath), FALSE);
    //    unixSockFd = createAndBindUnixSocket(filePath);
    //    FD_SET(unixSockFd, &fdSet);

    // Create interface sockets
    totalIfaceSock = createIfaceSockets(&ifaceSockList, &fdSet);

    // Read incoming packets on all sockets
    readAllSockets(unixSockFd, ifaceSockList, totalIfaceSock, fdSet, routes);

    free(ifaceSockList);

    unlink(filePath);
    Close(unixSockFd);
}

