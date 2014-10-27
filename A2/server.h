#ifndef _SERVER_H
#define _SERVER_H

#include "common.h"
#include "unprtt.h"

typedef struct client_request {
    struct sockaddr_in cliaddr;
    pid_t childpid;
    struct client_request *next;
} ClientRequest;

typedef struct send_window_node {
    TcpPckt packet;         // Sending Packet
    int isPresent;          // If any packet is present at this node
    int numOfRetransmits;   // Number of retransmissions
    //timestamp ???
} SendWinNode;

typedef struct send_window_queue {
    SendWinNode *wnode;     // Sending window containing packets
    int winSize;            // Total sending window size
    int cwin;               // Current window size
    int oldestSeqNum;       // Oldest sequence number in window
    int nextNewSeqNum;      // Next new sequence number
    int ssfresh;
} SendWinQueue;



#endif /* !_SERVER_H */
