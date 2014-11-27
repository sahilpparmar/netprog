/*
################################ Message format ###############################
| IP Multicast Address | Port number | Current Index | MAX HOPS| IP LIST       |
| STRING NUMBER        |   UINT_16   |   UINT_16     | UINT_16 | ARRAY IP[MAX] |
|##############################################################################
*/
#define IPLEN 30
#define MAXHOPS 50
typedef char IP[IPLEN];
typedef struct {
    IP multicastIP;
    int multicastPort;
    int curIndex;
    int maxHops;
    IP tourList[MAXHOPS];
}TourPayload;

