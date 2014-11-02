#include "client.h"
#include "unpthread.h"
#include "assert.h"
#include "math.h"

pthread_mutex_t QueueMutex = PTHREAD_MUTEX_INITIALIZER;

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
    printf(KCYM "Receving Window =>\t");
    printf("Advertised WinSize: %d    Contents:", RecWinQ->advertisedWin);
    for (i = 0; i < RecWinQ->winSize; i++) {
        if (IS_PRESENT(RecWinQ, i))
            printf(" %d", GET_SEQ_NUM(RecWinQ, i));
        else
            printf(" x");
    }
    printf( RESET "\n");
}

static int addPacketToRecWin(RecWinQueue *RecWinQ, TcpPckt *packet, int packetSize) {
    if (packet->seqNum == FIN_SEQ_NO) {
        printf(KYEL "FIN packet received\n" RESET);
        return FIN_SEQ_NO;
    } else if (packet->seqNum == PROBE_SEQ_NO) {
        printf(KYEL "PROBE packet received\n" RESET);
        return PROBE_SEQ_NO;
    }

    RecWinNode *wnode = GET_WNODE(RecWinQ, packet->seqNum);
    printf(KYEL);
    if (wnode->isPresent) {
        // Duplicate packet arrived
        assert((wnode->packet.seqNum == packet->seqNum) && "Invalid packet seq num");
        printf("DUPLICATE packet received\n");

    } else if (RecWinQ->nextSeqExpected > packet->seqNum) {
        printf("OLD packet received\n");

    } else {
        // New packet arrived
        fillPckt(&wnode->packet, packet->seqNum, packet->ackNum, packet->winSize,
                packet->data, packetSize - HEADER_LEN);
        wnode->dataSize = packetSize - HEADER_LEN;
        wnode->isPresent = 1;

        if (RecWinQ->nextSeqExpected == packet->seqNum) {
            int wInd;
            do {
                RecWinQ->nextSeqExpected++;
                RecWinQ->advertisedWin--;
                wInd = GET_INDEX(RecWinQ, RecWinQ->nextSeqExpected);
            } while ((IS_PRESENT(RecWinQ, wInd)) && (GET_SEQ_NUM(RecWinQ, wInd) == RecWinQ->nextSeqExpected));
        }
        printf("NEW packet received\n");
    }
    printf(RESET);

    printRecWindow(RecWinQ);
    return packet->seqNum;
}

int initializeRecWinQ(RecWinQueue *RecWinQ, TcpPckt *firstPacket, int packetSize, int recWinSize) {
    RecWinQ->wnode           = (RecWinNode*) calloc(recWinSize, sizeof(RecWinNode));
    RecWinQ->winSize         = recWinSize;
    RecWinQ->advertisedWin   = recWinSize;
    RecWinQ->nextSeqExpected = DATA_SEQ_NO;
    RecWinQ->consumerSeqNum  = DATA_SEQ_NO;

    // Add first packet in receving window
    return addPacketToRecWin(RecWinQ, firstPacket, packetSize);
}


void sendAck(RecWinQueue *RecWinQ, int fd) { 
    char buf[ACK_PRINT_BUFF];
    TcpPckt packet;
    
    sprintf(buf, "Sending Ack No %d\t", RecWinQ->nextSeqExpected);
    
    fillPckt(&packet, CLI_DEF_SEQ_NO, RecWinQ->nextSeqExpected,
        RecWinQ->advertisedWin, NULL, 0); //No data

    writeWithPacketDrops(fd, &packet, HEADER_LEN, buf);

}

static void sendFinAck(RecWinQueue *RecWinQ, int fd) {
    TcpPckt packet;
    
    fillPckt(&packet, CLI_DEF_SEQ_NO, FIN_ACK_NO,
        RecWinQ->advertisedWin, NULL, 0);

    writeWithPacketDrops(fd, &packet, HEADER_LEN, "Sending FIN-ACK\t\t");

}

static void sendProbeAck(RecWinQueue *RecWinQ, int fd) {
    TcpPckt packet;

    fillPckt(&packet, CLI_DEF_SEQ_NO, PROBE_ACK_NO,
        RecWinQ->advertisedWin, NULL, 0);

    writeWithPacketDrops(fd, &packet, HEADER_LEN, "Sending PROBE-ACK\t");

}

int writeWithPacketDrops(int fd, void *ptr, size_t nbytes, char *msg) {
    printf("\n%s: ", msg);
    if (isPacketLost()) {
        return -1;
    }
    printf(KGRN _4TABS "Sent\n" RESET);
    Writen(fd, ptr, nbytes);
    return 1;
}

int readWithPacketDrops(int fd, TcpPckt *packet, size_t nbytes, char *msg) {
    int n;
    while (1) {
        n = Read(fd, (void *) packet, nbytes);
        printf("\n%s =>  ", msg);
        if (packet->seqNum >= DATA_SEQ_NO)
            printf("Seq num: %d", packet->seqNum);
        else
            printf(_2TABS);
        if (!isPacketLost()) {
            break;
        }
    }
    printf(KGRN _4TABS "Received\n" RESET);
    return n;
}

static void *producerFunction(void *arg) {
    TcpPckt packet;
    uint32_t seqNum;
    char recvBuf[MAX_PAYLOAD+1];
    int len, terminate;

    struct prodConsArg *prodCons= ((struct prodConsArg *)arg);

    int sockfd = *(prodCons->sockfd);
    RecWinQueue *RecWinQ = (prodCons->queue);

    while (1) {

        len = readWithPacketDrops(sockfd, &packet, DATAGRAM_SIZE,
                "Receiving next file packet");

        Pthread_mutex_lock(&QueueMutex);
        seqNum = addPacketToRecWin(RecWinQ, &packet, len);
        Pthread_mutex_unlock(&QueueMutex);

        if (seqNum == FIN_SEQ_NO) {
            // Received FIN - terminate connection
            terminateConnection(sockfd, RecWinQ, &packet, len);
            break;
        } else if (seqNum == PROBE_SEQ_NO) {
            sendProbeAck(RecWinQ, sockfd);
        } else {
            sendAck(RecWinQ, sockfd);
        }
    }
}

static void *consumerFunction(void *arg) {
    TcpPckt packet;
    unsigned int seqNum, ackNum, winSize;
    char recvBuf[MAX_PAYLOAD+1];
    int len;

    struct prodConsArg *prodCons= ((struct prodConsArg *)arg);
    RecWinQueue *RecWinQ = (prodCons->queue);

    int sleepTime;

    while (1) {
        sleepTime = (-1 * in_read_delay * log(drand48()));
        usleep(sleepTime*1000);
       
        Pthread_mutex_lock(&QueueMutex);
        if ((RecWinQ->consumerSeqNum) != (RecWinQ->nextSeqExpected)) {
            printf(KMAG "\n - - - - - - - - - - - - - Inside Consumer Thread - - - - - - - - - - - -\n" RESET);
            int i, nBytes;

            printf("\nReading Packet(s) =>");
            for (i = RecWinQ->consumerSeqNum, nBytes = 0; i != RecWinQ->nextSeqExpected; i++) {
                assert(IS_PRESENT(RecWinQ, GET_INDEX(RecWinQ, i)) &&
                        "Invalid Packet Contents in receiving window");

                printf("   %d", i);

                GET_WNODE(RecWinQ, i)->isPresent = 0;
                RecWinQ->advertisedWin++;
                nBytes += GET_DATA_SIZE(RecWinQ, GET_INDEX(RecWinQ, i));
            }
            printf("\n");
            printRecWindow(RecWinQ);

            printf("File Data Contents => (Total Bytes: %d)\n", nBytes);
            while ((RecWinQ->consumerSeqNum) != (RecWinQ->nextSeqExpected)) {
                int wIndex = GET_INDEX(RecWinQ, RecWinQ->consumerSeqNum);

                readPckt(GET_PACKET(RecWinQ, wIndex),
                        (GET_DATA_SIZE(RecWinQ, wIndex)+ HEADER_LEN),
                        &seqNum, &ackNum, &winSize, recvBuf);

                printf("%s", recvBuf);

                RecWinQ->consumerSeqNum++;

                if (GET_DATA_SIZE(RecWinQ, wIndex) != MAX_PAYLOAD) {
                    printf(KMAG "\n\n - - - - - - - - - - - - - Exiting Consumer Thread - - - - - - - - - - - -\n" RESET);
                    Pthread_mutex_unlock(&QueueMutex);
                    return;
                }
            }
            printf(KMAG "\n\n - - - - - - - - - - - - - Exiting Consumer Thread - - - - - - - - - - - -\n" RESET);
        }
        Pthread_mutex_unlock(&QueueMutex);
    }
}

int fileTransfer(int *sockfd, RecWinQueue *RecWinQ) {

    pthread_t prodThread, consThread;
    struct prodConsArg arguments;

    arguments.sockfd = sockfd;
    arguments.queue = RecWinQ; 

    Pthread_create(&prodThread, NULL, &producerFunction, (void *)&arguments);
    Pthread_create(&consThread, NULL, &consumerFunction, (void *)&arguments);

    pthread_join(prodThread, NULL);
    pthread_join(consThread, NULL);

    printf("\nFile Transfer successfully completed\n");
}

void terminateConnection(int sockfd, RecWinQueue *RecWinQ, TcpPckt *packet, int len) {
    if (len > HEADER_LEN) {
        // Server terminated due to error
        packet->data[len - HEADER_LEN] = '\0';
        printf(KRED "Server Error: %s\n" RESET, packet->data);
    }

    sendFinAck(RecWinQ, sockfd);
}

