#ifndef _CLIENT_H
#define _CLIENT_H

#include "common.h"

#define GET_INDEX(winQ, packet) ((packet->seqNum)%(winQ->winSize))
#define GET_WNODE(winQ, packet) (&(winQ->wnode[GET_INDEX(winQ, packet)]))
#define IS_PRESENT(winQ, ind) (winQ->wnode[ind].isPresent)
#define GET_PACKET(winQ, ind) (&(winQ->wnode[ind].packet))
#define GET_SEQ_NUM(winQ, ind) (GET_PACKET(winQ, ind)->seqNum)

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
int writeWithPacketDrops(int fd, SA* sa, int salen, void *ptr, size_t nbytes, char *msg);
int readWithPacketDrops(int fd, void *ptr, size_t nbytes, char *msg);

void initializeRecWinQ(RecWinQueue *RecWinQ, TcpPckt *firstPacket, int packetSize, int recWinSize);
int fileTransfer(int sockfd, RecWinQueue *RecWinQ);

#endif /* !_CLIENT_H */
