#ifndef _SERVER_H
#define _SERVER_H

#include "common.h"
#include "unprtt.h"

#define GET_OLDEST_SEQ_IND(sendWinQ) (sendWinQ->oldestSeqNum%sendWinQ->winSize)
#define GET_OLDEST_SEQ_WNODE(sendWinQ) (&(sendWinQ->wnode[GET_OLDEST_SEQ_IND(sendWinQ)]))
#define IS_ADDITIVE_INC(sendWinQ) (sendWinQ->ssThresh <= sendWinQ->cwin)

typedef struct client_request {
    struct sockaddr_in cliaddr;
    pid_t childpid;
    struct client_request *next;
} ClientRequest;

typedef struct send_window_node {
    TcpPckt packet;         // Sending Packet
    int dataSize;           // Length of data in packet
    int isPresent;          // If any packet is present at this node
    int numOfRetransmits;   // Number of retransmissions
    uint32_t timestamp;     // Timestamp of packet
} SendWinNode;

typedef struct send_window_queue {
    SendWinNode *wnode;     // Sending window containing packets
    int winSize;            // Total sending window size
    int cwin;               // Current window size
    int ssThresh;           // SSThresh value
    int oldestSeqNum;       // Oldest sequence number in window
    int nextNewSeqNum;      // Next new sequence number
    int nextSendSeqNum;     // Next Sequence number to be sent
    int advertisedWin;      // Receiver's advertised window size
    int additiveAckNum;     // Ack Num for which we increase Cwin under AIMD
} SendWinQueue;

void initializeSendWinQ(SendWinQueue *SendWinQ, int sendWinSize, int recWinSize, int nextSeqNum);
void sendFile(SendWinQueue *SendWinQ, int connFd, int fileFd, struct rtt_info rttInfo);
void terminateConnection(int connFd, char *errMsg);

#endif /* !_SERVER_H */
