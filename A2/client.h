#ifndef _CLIENT_H
#define _CLIENT_H

#include "common.h"

typedef struct rec_window_node {
    TcpPckt packet;         // Packet received
    int dataSize;           // Length of data in packet
    int isPresent;          // If any packet is present at this node
} RecWinNode;

typedef struct rec_window_queue {
    RecWinNode *wnode;      // Receiving window containing packets
    int winSize;            // Total receiving window size
    int advertisedWin;      // Advertised window Size
    int nextSeqExpected;    // Next expected sequence number
    int consumerSeqNum;     // Seq num at which consumer will start reading
} RecWinQueue;

extern float in_packet_loss;
extern int   in_read_delay;
int writeWithPacketDrops(int fd, void *ptr, size_t nbytes, char *msg);
int readWithPacketDrops(int fd, TcpPckt *packet, size_t nbytes, char *msg);

int initializeRecWinQ(RecWinQueue *RecWinQ, TcpPckt *firstPacket, int packetSize, int recWinSize);
int fileTransfer(int *sockfd, RecWinQueue *RecWinQ);
void terminateConnection(int sockfd, RecWinQueue *RecWinQ, TcpPckt *packet, int len);

#endif /* !_CLIENT_H */
