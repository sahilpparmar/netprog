#include "client.h"
#include "unpthread.h"
#include "assert.h"
#include "math.h"

struct prodConsArg{
    int *sockfd;
    RecWinQueue *queue; 
};

static int isPacketLost() {
    double rval = drand48();
    //printf("%f %f", rval, in_packet_loss);
    if (rval > in_packet_loss) {
        return 0;
    }
    err_msg(KRED _4TABS "Dropped" RESET);
    return 1;
}

static void printRecWinNode(RecWinQueue *RecWinQ, int ind) {
    printf("Receving Window [%d] => ", ind); 
    if (IS_PRESENT(RecWinQ, ind)) {
        TcpPckt *packet = GET_PACKET(RecWinQ, ind);
        printf("SeqNum: %d\nData Contents:\n%s\n", packet->seqNum, packet->data);
    } else {
        printf("Empty\n");
    }
}

static void printRecWindow(RecWinQueue *RecWinQ) {
    int i;
    printf(KBLU "Receving Window =>\t");
    printf("Next Expected Seq No: %d    Advertised WinSize: %d    Contents:",
            RecWinQ->nextSeqExpected, RecWinQ->advertisedWin);
    for (i = 0; i < RecWinQ->winSize; i++) {
        if (IS_PRESENT(RecWinQ, i))
            printf(" %d", GET_SEQ_NUM(RecWinQ, i));
        else
            printf(" x");
    }
    printf( RESET "\n");
}

static int addPacketToRecWin(RecWinQueue *RecWinQ, TcpPckt *packet, int dataSize) {
    RecWinNode *wnode = GET_WNODE(RecWinQ, packet->seqNum);

    if (wnode->isPresent) {
        assert((wnode->packet.seqNum == packet->seqNum) && "Invalid packet seq num");
        printRecWindow(RecWinQ);
        return 0;
    }

    fillPckt(&wnode->packet, packet->seqNum, packet->ackNum, packet->winSize, packet->data, dataSize);
    wnode->dataSize = dataSize;
    wnode->isPresent = 1;

    if (RecWinQ->nextSeqExpected == packet->seqNum) {
        int wInd;
        do {
            RecWinQ->nextSeqExpected++;
            RecWinQ->advertisedWin--;
            wInd = GET_INDEX(RecWinQ, RecWinQ->nextSeqExpected); 
        } while ((IS_PRESENT(RecWinQ, wInd)) && (GET_SEQ_NUM(RecWinQ, wInd) == RecWinQ->nextSeqExpected));
    }

    printRecWindow(RecWinQ);
    return 1;
}

void initializeRecWinQ(RecWinQueue *RecWinQ, TcpPckt *firstPacket, int packetSize, int recWinSize) {
    RecWinQ->wnode           = (RecWinNode*) calloc(recWinSize, sizeof(RecWinNode));
    RecWinQ->winSize         = recWinSize;
    RecWinQ->advertisedWin   = recWinSize;
    RecWinQ->nextSeqExpected = DATA_SEQ_NO;
    RecWinQ->consumerSeqNum  = DATA_SEQ_NO;

    // Add first packet in receving window
    addPacketToRecWin(RecWinQ, firstPacket, packetSize-HEADER_LEN);
}

// Used by client to send Acks
void sendAck(RecWinQueue *RecWinQ, int fd) { 
    char buf[ACK_PRINT_BUFF];
    TcpPckt packet;
    
    sprintf(buf, "Sending Ack No %d\t", RecWinQ->nextSeqExpected);
    
    fillPckt(&packet, CLI_DEF_SEQ_NO, RecWinQ->nextSeqExpected,
        RecWinQ->advertisedWin, NULL, 0); //No data

    writeWithPacketDrops(fd, NULL, 0, &packet, HEADER_LEN, buf);

}

void sendFinAck(RecWinQueue *RecWinQ, int fd) { 
    TcpPckt packet;
    
    fillPckt(&packet, FIN_ACK_SEQ_NO, CLI_DEF_ACK_NO,
        RecWinQ->advertisedWin, NULL, 0); //No data

    writeWithPacketDrops(fd, NULL, 0, &packet, HEADER_LEN, "Sending FIN-ACK\t\t");

}

int writeWithPacketDrops(int fd, SA* sa, int salen, void *ptr, size_t nbytes, char *msg) {
    printf("\n%s: ", msg);
    if (isPacketLost()) {
        return -1;
    }
    printf(KGRN _4TABS "Sent\n" RESET);
    Writen(fd, ptr, nbytes);//TODO , 0, sa, salen);
    return 1;
}

int readWithPacketDrops(int fd, void *ptr, size_t nbytes, char *msg) {
    int n;
    while (1) {
        printf("\n%s: ", msg);
        n = Read(fd, ptr, nbytes);//, 0, NULL, NULL);
        if (!isPacketLost()) {
            break;
        }
    }
    printf(KGRN _4TABS "Received\n" RESET);
    return n;
}

void *producerFunction(void *arg) {
    TcpPckt packet;
    uint32_t seqNum, ackNum, winSize;
    char recvBuf[MAX_PAYLOAD+1];
    int len;

    struct prodConsArg *prodCons= ((struct prodConsArg *)arg);

    int sockfd = *(prodCons->sockfd);
    RecWinQueue *RecWinQ = (prodCons->queue);

    while (1) {
        len = readWithPacketDrops(sockfd, (void *) &packet, DATAGRAM_SIZE,
                "Receiving next file packet");
        readPckt(&packet, len, &seqNum, &ackNum, &winSize, recvBuf);
        if (seqNum == FIN_SEQ_NO) {
            printf("FIN Packet Received\n");
            // TODO: Check for errors and report
            break;
        }
        printf("Seq num: %d\t Bytes Read: %d\n", seqNum, len);
        if (addPacketToRecWin(RecWinQ, &packet, len - HEADER_LEN) == 1) {
            printf("New packet received\n");
//            printf("Data Contents:\n%s\n", recvBuf);
        } else {
            printf("Duplicate packet received\n");
        }
        sendAck(RecWinQ, sockfd);
    } 
    sendFinAck(RecWinQ, sockfd);
}

void *consumerFunction(void *arg) {
    TcpPckt packet;
    unsigned int seqNum, ackNum, winSize;
    char recvBuf[MAX_PAYLOAD+1];
    int len;

    struct prodConsArg *prodCons= ((struct prodConsArg *)arg);
    RecWinQueue *RecWinQ = (prodCons->queue);


    //TODO Logic for randomly sleeping 
    float sleepTime = 2;
    
    while(1) {

        sleepTime = (-1 * log(drand48()) * (in_read_delay/1000));
        printf("Consumer Going to sleep for %f\n",sleepTime);
        sleep(sleepTime);

        while((RecWinQ->consumerSeqNum) != (RecWinQ->nextSeqExpected)){
            assert(IS_PRESENT(RecWinQ, GET_INDEX(RecWinQ,RecWinQ->consumerSeqNum)) == 1);
            int wIndex =GET_INDEX(RecWinQ,RecWinQ->consumerSeqNum); 
            
//            printf("Queue Stats winSize: %d advertisedWin: %d 
//                    nextSeqExpected: %d consumerSeqNum: %d\n", RecWinQ->winSize, 
//                    RecWinQ->advertisedWin, RecWinQ->nextSeqExpected,  
//                    RecWinQ->consumerSeqNum);


            readPckt(GET_PACKET(RecWinQ, wIndex),
                    (GET_DATA_SIZE(RecWinQ, wIndex)+ HEADER_LEN),
                    &seqNum, &ackNum, &winSize, recvBuf);
            
            printf("Seq num: %d\t Bytes Read: %d\n", seqNum, 
                (GET_DATA_SIZE(RecWinQ, wIndex)+ HEADER_LEN));
        
            printf("Data Contents:\n%s\n", recvBuf);
            GET_WNODE(RecWinQ, RecWinQ->consumerSeqNum)->isPresent = 0; 
            (RecWinQ->consumerSeqNum)++;
            (RecWinQ->advertisedWin)++;
            
            printRecWindow(RecWinQ);
            if (GET_DATA_SIZE(RecWinQ, wIndex) != MAX_PAYLOAD ) { 
                // TODO: Check for errors and report
                return;
            }


        }

    }

}

void startProdConsum(pthread_t *producerThread, pthread_t *consumerThread, struct prodConsArg *arg) {
    Pthread_create(&(*producerThread), NULL, &producerFunction, (void *)arg);
    Pthread_create(&(*consumerThread), NULL, &consumerFunction, (void *)arg);
}

int fileTransfer(int *sockfd, RecWinQueue *RecWinQ) {

    pthread_t prodThread, consThread;
    struct prodConsArg arguments;

    arguments.sockfd = sockfd;
    arguments.queue = RecWinQ; 

    startProdConsum(&prodThread, &consThread, &arguments);
    pthread_join(prodThread, NULL);
    pthread_join(consThread, NULL);

    // TODO: Send a FIN-ACK
    printf("\nFile Transfer successfully completed\n");
}

