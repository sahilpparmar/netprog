#ifndef _ODR_H
#define _ODR_H

#define PROTOCOL_NUMBER 0x5454
#define IPLEN           30      // bytes
#define MACLEN          6       // bytes
#define MAX_PAYLOAD_LEN 100     // bytes
#define FP_MAP_STALE_VAL 5.0    // sec
#define TTL_HOP_COUNT    10     // hops
#define FIRST_CLI_PORTNO 4000
#define FIRST_BCAST_ID   8000

// Packet Type
typedef enum {
    RREQ,
    RREP,
    DATA
} packetType;

// ODR Packet
typedef struct {
    packetType type;
    char sourceIP[IPLEN];
    char destIP[IPLEN];
    uint32_t sourcePort;
    uint32_t destPort;
    uint32_t hopCount;
    uint32_t broadID;
    char Asent;
    char forceRedisc;
    char data[MAX_PAYLOAD_LEN];
} ODRPacket;

//Ethernet Frame
typedef struct {
    uint8_t destMAC[MACLEN]; 
    uint8_t sourceMAC[MACLEN];
    uint16_t protocol;
    ODRPacket packet; 
} EthernetFrame;

typedef struct {
    int ifaceNum;
    int ifaceSocket;
    uint8_t ifaceMAC[MACLEN];
} IfaceInfo;


typedef struct WaitingPacket {
    ODRPacket packet;  
    struct WaitingPacket *next;
} WaitingPacket;

// Routing Table
typedef struct {
    bool isValid;
    uint32_t broadID;
    uint32_t ifaceInd;
    uint8_t nextHopMAC[MACLEN];
    uint32_t hopCount;
    time_t timeStamp;
    WaitingPacket* waitListHead;
} RoutingTable; // The index of the routingTable array will give the destination index

typedef struct {
    char filePath[1024];
    int portNo;
    time_t timestamp;
    bool isValid;
} FilePortMap;

extern char filePath[1024], hostNode, hostIP[100];

void initFilePortMap();
int processUnixPacket(int sockfd, ODRPacket *packet);
int getNextBroadCastID();
int writeUnixSocket(int sockfd, char *srcIP, int srcPort, int destPort, char *msg);

#endif /* !_ODR_H */
