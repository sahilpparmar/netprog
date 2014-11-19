#ifndef _ODR_H
#define _ODR_H

#define IPLEN 30
#define PROTOCOL_NUMBER 0x5445
#define MAX_INTERFACE 7 //TODO
#define TOTAL_NODES 10
#define STALENESS 5 // TODO get from client
#define MAX_PAYLOAD_LEN 100 //TODO verify

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
    bool Asent;
    bool forceRedisc; 
    char data[MAX_PAYLOAD_LEN];
} ODRPacket;

//Ethernet Frame
typedef struct {
    uint8_t destMAC[6]; 
    uint8_t sourceMAC[6];
    uint8_t protocol[2];
    ODRPacket packet; 
} EthernetFrame;

typedef struct {
    int ifaceNum;
    int ifaceSocket;
    uint8_t ifaceMAC[6];
} IfaceInfo;


typedef struct WaitingPacket {
    ODRPacket packet;  
    struct WaitingPacket *next;
} WaitingPacket;

// Routing Table
typedef struct {
    bool isValid;
    uint32_t broadID;
    uint32_t ifaceNum;
    uint8_t nextHopMAC[6];
    uint32_t hopCount;
    uint32_t timeStamp;
    WaitingPacket* waitListHead;
} RoutingTable; // The index of the routingTable array will give the destination index

typedef struct {
    char filePath[1024];
    int portNo;
    //TODO timestamp
} FilePortMap;

extern char filePath[1024], hostNode, hostIP[100];

void initFilePortMap();
void processUnixPacket(int sockfd);

#endif /* !_ODR_H */
