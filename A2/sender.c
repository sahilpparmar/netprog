#include "server.h"

static int getNextNewPacket(TcpPckt *pckt, uint32_t seq, uint32_t ack, uint32_t winSize, int fileFd) {
    char buf[MAX_PAYLOAD+1];
    int n = Read(fileFd, buf, MAX_PAYLOAD);
    return fillPckt(pckt, seq, ack, winSize, buf, n);
}

static void printSendWindow(SendWinQueue *SendWinQ) {
    int i;
    printf(KBLU "Sending Window =>  ");
    printf("Cwin: %d  SSThresh: %d  Contents:", SendWinQ->cwin, SendWinQ->ssThresh);
    for (i = 0; i < SendWinQ->winSize; i++) {
        if (IS_PRESENT(SendWinQ, i))
            printf(" %d", GET_SEQ_NUM(SendWinQ, i));
        else
            printf(" x");
    }
    printf( RESET "\n");
}

static SendWinNode* addPacketToSendWin(SendWinQueue *SendWinQ, TcpPckt *packet, int dataSize) {
    SendWinNode *wnode = GET_WNODE(SendWinQ, packet->seqNum);
    fillPckt(&wnode->packet, packet->seqNum, packet->ackNum, packet->winSize, packet->data, dataSize);
    wnode->dataSize = dataSize;
    wnode->isPresent = 1;
    wnode->numOfRetransmits = 0;

    // Update nextNewSeqNum
    if (SendWinQ->nextNewSeqNum == packet->seqNum) {
        SendWinQ->nextNewSeqNum++;
    }

    return wnode;
}

static void zeroOutRetransmitCnts(SendWinQueue *SendWinQ) {
    int i;
    for (i = 0; i < SendWinQ->winSize; i++) {
        SendWinQ->wnode[i].numOfRetransmits = 0;
    }
}

void initializeSendWinQ(SendWinQueue *SendWinQ, int sendWinSize, int recWinSize, int nextSeqNum) {
    SendWinQ->wnode         = (SendWinNode*) calloc(sendWinSize, sizeof(SendWinNode));
    SendWinQ->winSize       = sendWinSize;
    SendWinQ->cwin          = 1;
    SendWinQ->oldestSeqNum  = nextSeqNum;
    SendWinQ->nextNewSeqNum = nextSeqNum;
    SendWinQ->ssThresh      = sendWinSize;
}

static void incrementCwin(SendWinQueue *SendWinQ, int allAcksReceived, int advertisedWin) {
    if ((allAcksReceived && IS_ADDITIVE_INC(SendWinQ)) ||
        !(allAcksReceived || IS_ADDITIVE_INC(SendWinQ))
    ) {
        SendWinQ->cwin = min(SendWinQ->cwin + 1, min(SendWinQ->winSize, advertisedWin));
    }
}

static sigjmp_buf jmpToSendFile, jmpToTerminateConn;

static void sigAlarmForSendingFile(int signo) {
    siglongjmp(jmpToSendFile, 1);
}

static void sigAlarmForSendingFIN(int signo) {
    siglongjmp(jmpToTerminateConn, 1);
}

void sendFile(SendWinQueue *SendWinQ, int connFd, int fileFd, struct rtt_info rttInfo) {
    SendWinNode *wnode;
    TcpPckt packet;
    uint32_t seqNum, ackNum, winSize, expectedAckNum;
    int i, len, done, numPacketsSent, dupAcks;
    struct itimerval timer;

    Signal(SIGALRM, sigAlarmForSendingFile);

    done = 0;
    while (!done) {
        zeroOutRetransmitCnts(SendWinQ);

sendAgain:
        // Send Packets
        seqNum = SendWinQ->oldestSeqNum;

        if (SendWinQ->cwin == 0) {
            // Congestion window size is 0. Send a Probe Message every PROBE_TIMER seconds.
            sleep(PROBE_TIMER/1000);
            len = fillPckt(&packet, PROBE_SEQ_NO, 0, 0, NULL, 0);
            Writen(connFd, (void *) &packet, len);
            printf(KYEL "\nPROBE packet Sent to check receiver's window size\n" RESET);

        } else {
            printf("\nPacket(s) Sent =>");
            for (i = 0; i < SendWinQ->cwin; i++) {

                if (seqNum < SendWinQ->nextNewSeqNum) {
                    // Packet already in sending window
                    int wInd = seqNum % SendWinQ->winSize;
                    assert(IS_PRESENT(SendWinQ, wInd) && "Packet should be present");
                    assert((seqNum == GET_SEQ_NUM(SendWinQ, wInd)) && "Invalid Seq Num of Sending Packet");

                    len = GET_DATA_SIZE(SendWinQ, wInd);
                    wnode = &SendWinQ->wnode[wInd];
                    wnode->numOfRetransmits++;
                } else {
                    // Get new packet and add to sending window
                    len = getNextNewPacket(&packet, seqNum, 0, 0, fileFd);
                    wnode = addPacketToSendWin(SendWinQ, &packet, len);
                }

                // Send packet and update timestamp
                Writen(connFd, (void *) &wnode->packet, len);
                wnode->timestamp = rtt_ts(&rttInfo);

                printf("   %d", seqNum);

                seqNum++;

                // No more file contents to send
                if (len != DATAGRAM_SIZE) {
                    done = 1;
                    break;
                }
            }
            printf("\n");
            printSendWindow(SendWinQ);
        }

        setTimer(&timer, rtt_start(&rttInfo));

        if (sigsetjmp(jmpToSendFile, 1) != 0) {
            printf(KRED "Receving ACKs => TIMEOUT\n" RESET);
            if (SendWinQ->cwin != 0) {
                int retransmitCnt = GET_OLDEST_SEQ_WNODE(SendWinQ)->numOfRetransmits;
                if (rtt_timeout(&rttInfo, retransmitCnt)) {
                    char *str = "Server Child Terminated due to 12 Timeouts";
                    printf(KRED); err_msg(str); printf(RESET);
                    break;
                }
                done = 0;
                // Multiplicative Decrease: Set SSThresh (Cwin / 2) and Cwin = 1
                SendWinQ->ssThresh = SendWinQ->cwin / 2;
                SendWinQ->cwin = 1;
            }
            goto sendAgain;
        } 

        expectedAckNum = seqNum;
        dupAcks = 0;

        // Receive ACKs
        while (1) {
            len = Read(connFd, (void *) &packet, DATAGRAM_SIZE);
            readPckt(&packet, len, NULL, &ackNum, &winSize, NULL);
            printf("\nACK Received =>  ACK num: %d\t Advertised Win: %d\n", ackNum, winSize);

            incrementCwin(SendWinQ, 0, winSize);

            if (SendWinQ->oldestSeqNum == ackNum) {
                dupAcks++;
                if (dupAcks == 3) {
                    printf(KRED "3 Duplicate ACKs received. Enabling Fast Retransmit.\n" RESET);
                    done = 0;
                    // Fast Recovery Mechanism: Set SSThresh and Cwin = (Cwin / 2)
                    SendWinQ->ssThresh = SendWinQ->cwin / 2;
                    SendWinQ->cwin = max(SendWinQ->ssThresh, 1);
                    break;
                } else {
                    printf(KYEL "%d Duplicate ACK(s) received\n" RESET, dupAcks);
                }
            } else {
                int once = 0;
                while (SendWinQ->oldestSeqNum < ackNum) {
                    int wInd = GET_OLDEST_SEQ_IND(SendWinQ);
                    assert(IS_PRESENT(SendWinQ, wInd) && "Packet should be present");
                    assert((SendWinQ->oldestSeqNum == GET_SEQ_NUM(SendWinQ, wInd)) &&
                            "Invalid Seq Num of Sending Packet");

                    if (!once) {
                        rtt_stop(&rttInfo, SendWinQ->wnode[wInd].timestamp);
                        once = 1;
                    }
                    SendWinQ->wnode[wInd].isPresent = 0;
                    SendWinQ->oldestSeqNum++;
                }
                printSendWindow(SendWinQ);
                dupAcks = 0;
            }

            if (expectedAckNum == ackNum) {
                // All packets successfully sent and acknowledged
                incrementCwin(SendWinQ, 1, winSize);
                break;
            }
        }

        setTimer(&timer, 0);
    }
}

void terminateConnection(int connFd, char *errMsg) {
    TcpPckt finPacket, finAckPacket;
    int retransmitCount, len;
    struct itimerval timer;

    Signal(SIGALRM, sigAlarmForSendingFIN);
    retransmitCount = 0;
    len = fillPckt(&finPacket, FIN_SEQ_NO, 0, 0, errMsg, strlen(errMsg));

sendFINAgain:
    // Send a FIN to terminate connection
    printf(KYEL "\nFIN packet Sent to terminate connection\n" RESET);
    Writen(connFd, (void *) &finPacket, len);
    retransmitCount++;

    setTimer(&timer, FIN_ACK_TIMER);

    if (sigsetjmp(jmpToTerminateConn, 1) != 0) {
        if (retransmitCount >= MAX_RETRANSMIT) {
            char *str = "Server Child Terminated due to 12 Timeouts";
            printf(KRED); err_msg(str); printf(RESET);
            return;
        }
        printf(KRED "TIMEOUT\n" RESET);
        goto sendFINAgain;
    }

    // Recv FIN-ACK from client
    printf(KYEL "Receving FIN-ACK => " RESET);
    do {
        Read(connFd, (void *) &finAckPacket, DATAGRAM_SIZE);
    } while (finAckPacket.seqNum != FIN_ACK_SEQ_NO);

    printf(KGRN "Received\n" RESET);
    printf(RESET);
    setTimer(&timer, 0);
}

