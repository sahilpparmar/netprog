#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "errno.h"
#include "hw_addrs.h"
#include "common.h"
#include "odr.h"

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
void printPacket(ethernetFrame *etherFrame,unsigned int length) {

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
        waitingFrame = (routes[destIndex])->waitListHead;
        while (waitingFrame != NULL) {
            waitingFrame = waitingFrame->next;
        }
        (routes[destIndex])->waitListHead = NULL;
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

        routeEntry->timeStamp = (unsigned int) time (NULL); 
        return True;
    }

    return False;
}

int sendAllInterface(ODRPacket *packet, int exceptInterface, int nextHop, unsigned char nextHopMAC[], unsigned int hopCount, routingTable *routes) {

    int retVal;
    int index;

    for(index = 0; index < totalSockets; index++) {
        send_result = sendto(sockets[index], ,ETH_FRAME_LEN, 0, (struct sockaddr *)&)
        
    }
    send_result = sendto(s, buffer, ETH_FRAME_LEN, 0, 
                      (struct sockaddr*)&socket_address, sizeof(socket_address));
    if (send_result == -1) {
        pr
    }

}

/*
int  sendonInterface(int index, int nextHop, unsigned char nextHopMAC[], unsigned int hopCount, routingTable *routes, int* sockets ) {
}
*/

/*

int handleRREQ(ODRPacket *packet, unsigned char nextHopMac[6], routingTable *routes, int* sockets, int incomingInter, int totalSockets,int sourceIndex ) {
    // Return 0 - Nothing needs to be done: New entry - Send RREQs
    // Return 1 - Have the entry, so sending RREP to the requestor as well as send RREQs on other interfaces with blah
    // Check if entry is present
    if ( (routes[sourceIndex]->nextHop == 0) // No entry in the routing table 
            || (routes[sourceIndex]->timestamp - STALENESS <= 0 ) // Route has been expired
            || (routes[sourceIndex]-> hopCount >= packet->hopCount) ) {// If its a better route
        createRouteEntry(sourceIndex, incomingInterf, nextHopMAC, packet->hopCount, routes );
        createUpdateRouteEntry(ethernetFrame *frame, int destIndex, int incomingInter, routingTable *routes,int inSocket); 


    }

    
    // Logic for flooding RREPS, or replying with RREQs
}
*/
void processFrame(ethernetFrame *etherFrame, routingTable *routes, int *sockets, int inSockIndex, int totalSockets) {
    
    unsigned char broadMAC[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned int  sourceIndex, destIndex;
    ODRPacket *packet;
    int retval = -1;

    packet = &(etherFrame->packet);

    switch(packet->type){
    
        case RREQ: // RREQ packet
            printf("RREQ packet received!\n");
            //retval = handleRREQ();
//            sourceIndex = getSourceIndex(packet->sourceIP);
 //           handleRREQ(packet, nextHopMac, routes, sockets, incomingInter, totalSockets);
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
int readSockets(int* sockets, int totalSockets, fd_set FDSet, routingTable* routes) {
    int maxfd, index;
    int length = 0; /*length of the received frame*/ 
    ethernetFrame etherFrame; /*Buffer for ethernet frame*/
    fd_set tempFDSet;

    maxfd = sockets[totalSockets-1] + 1;

    while(1) {
        tempFDSet = FDSet;
        Select(maxfd, &tempFDSet, NULL, NULL, NULL); //TODO Read on unix domain socket

        // Check which socket got a packet
        for (index = 0; index<totalSockets; index++) {
            if (FD_ISSET(sockets[index], &tempFDSet)) {
                length = recvfrom(sockets[index], &etherFrame, sizeof(etherFrame), 0, NULL, NULL);

                if(length < 0) {
                    printf("Error in receiving packet");
                }

                // Print out contents of received ethernet frame.
                printPacket(&etherFrame, length);

                processFrame(&etherFrame, routes, sockets, index, totalSockets);
            }// IF FD is set
        } // For loop

    } // while

}
int createSockets(int *socketList, int *totalSockets, fd_set *FDSet) {

    struct hwa_info	*hwa, *hwahead;

    int startInterface = 2; //TODO All interfaces apart from lo and eth0
    int index = 0;
    int i = 0;
    int maxfd = 0;
    int totalInterfaces = 0;
    int errnum = 0;

    fd_set fixedFDSet;
    struct sockaddr_ll listenFilter;


    printf("\n");

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next, totalInterfaces++);
    printf ("Interfaces: %d\n", totalInterfaces);
    totalInterfaces = totalInterfaces - 2; // Discarding eth0 and lo

    *totalSockets = totalInterfaces; // setting variables from the main function

    socketList = malloc(totalInterfaces * sizeof(int));

    FD_ZERO(&fixedFDSet);
    FD_SET(0, &fixedFDSet);

    memset(&listenFilter, 0, sizeof(listenFilter));
    listenFilter.sll_protocol = PROTOCOL_NUMBER;

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
        printInterface(hwa);

        if (hwa->if_index > startInterface) {
            // if the interface number is greater than 2 then make sockets on each interfaces
            if ((socketList[index] = socket(PF_PACKET, SOCK_RAW, htons(PROTOCOL_NUMBER))) < 0) {
                printf("Error in creating PF_PACKET socket for interface: %d\n\n", index + 3);
                exit (0);
            }

            FD_SET(socketList[index], &fixedFDSet);
            listenFilter.sll_ifindex = hwa->if_index;
            printf("Bind: %d\n\n", socketList[index]);
            Bind(socketList[index], (struct sockaddr *) &listenFilter, sizeof(listenFilter)); //TODO Bind error

            index++;
        }
    }

    //TODO Add unix domain socket
    *FDSet = fixedFDSet;
    free_hwa_info(hwahead);
    return;
}


int main()
{
    int totalSockets;
    fd_set FDSet;
    int *socketList;
    routingTable routes[TOTAL_NODES + 1];

    createSockets(socketList, &totalSockets, &FDSet);
    readSockets(socketList, totalSockets, FDSet, routes);

    free(socketList);

}
