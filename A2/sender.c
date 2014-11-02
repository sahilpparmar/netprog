#include "server.h"

static int getNextNewPacket(TcpPckt *pckt, uint32_t seq, uint32_t ack, uint32_t winSize, int fileFd) {
    char buf[MAX_PAYLOAD+1];
    int n = Read(fileFd, buf, MAX_PAYLOAD);
    return fillPckt(pckt, seq, ack, winSize, buf, n);
}

static void printSendWindow(SendWinQueue *SendWinQ) {
    int i, nextSendInd;

    printf(KCYM "Sending Window =>  ");
    printf("Cwin: %d  SSThresh: %d  Contents:", SendWinQ->cwin, SendWinQ->ssThresh);
    nextSendInd = GET_INDEX(SendWinQ, SendWinQ->nextSendSeqNum);

    for (i = 0; i < SendWinQ->winSize; i++) {
        if (i == nextSendInd) printf(" |");

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
static void incrementCwin(SendWinQueue *SendWinQ, int allAcksReceived) {
    if ((allAcksReceived && IS_ADDITIVE_INC(SendWinQ)) ||
        !(allAcksReceived || IS_ADDITIVE_INC(SendWinQ))
    ) {
        SendWinQ->cwin = min(SendWinQ->cwin + 1, SendWinQ->winSize);
    }
}

static void updateAdditiveAckNum(SendWinQueue *SendWinQ) {
    if (IS_ADDITIVE_INC(SendWinQ)) {
        SendWinQ->additiveAckNum = SendWinQ->oldestSeqNum + SendWinQ->cwin;
    } else {
        SendWinQ->additiveAckNum = 0;
    }
}

void initializeSendWinQ(SendWinQueue *SendWinQ, int sendWinSize, int recWinSize, int nextSeqNum) {
    SendWinQ->wnode          = (SendWinNode*) calloc(sendWinSize, sizeof(SendWinNode));
    SendWinQ->winSize        = sendWinSize;
    SendWinQ->cwin           = 1;
    SendWinQ->ssThresh       = sendWinSize;
    SendWinQ->oldestSeqNum   = nextSeqNum;
    SendWinQ->nextNewSeqNum  = nextSeqNum;
    SendWinQ->nextSendSeqNum = nextSeqNum;
    SendWinQ->advertisedWin  = recWinSize;
    updateAdditiveAckNum(SendWinQ);
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
    uint32_t seqNum, ackNum, winSize;
    int i, len, done, numPacketsSent, dupAcks;
    struct itimerval timer;
    sigset_t sigset;

    Signal(SIGALRM, sigAlarmForSendingFile);
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGALRM);

    done = 0;
    while (!done) {
        zeroOutRetransmitCnts(SendWinQ);

sendAgain:
        if (SendWinQ->advertisedWin == 0) {
            // Receiver's advertised winSize is 0. Send a Probe Message every PROBE_TIMER seconds.
            sleep(PROBE_TIMER/1000);
            len = fillPckt(&packet, PROBE_SEQ_NO, 0, 0, NULL, 0);
            Writen(connFd, (void *) &packet, len);
            printf(KYEL "\nPROBE packet Sent to check receiver's window size\n" RESET);

        } else {
            int once = 0;

            // Send Data Packets
            seqNum = SendWinQ->nextSendSeqNum;
            for (i = seqNum - SendWinQ->oldestSeqNum; i < min(SendWinQ->cwin, SendWinQ->advertisedWin); i++) {

                if (!once) {
                    printf("\nPacket(s) Sent ");
                    if (seqNum < SendWinQ->nextNewSeqNum) {
                        printf(KYEL "(Retransmission) =>" RESET);
                    } else {
                        printf(KGRN "(New) =>" RESET);
                    }
                    once = 1;
                }

                if (seqNum < SendWinQ->nextNewSeqNum) {
                    // Packet already in sending window
                    int wInd = GET_INDEX(SendWinQ, seqNum);
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
            if (once) {
                printf("\n");
                SendWinQ->nextSendSeqNum = seqNum;
                printSendWindow(SendWinQ);
            }
        }

        setTimer(&timer, rtt_start(&rttInfo));

        if (sigsetjmp(jmpToSendFile, 1) != 0) {
            printf(KRED "\nReceving ACKs => TIMEOUT\n" RESET);

            if (SendWinQ->advertisedWin != 0) {
                int retransmitCnt = GET_OLDEST_SEQ_WNODE(SendWinQ)->numOfRetransmits;
                if (rtt_timeout(&rttInfo, retransmitCnt)) {
                    char *str = "\nServer Child Terminated due to 12 Timeouts";
                    printf(KRED); err_msg(str); printf(RESET);
                    break;
                }
                done = 0;

                // Multiplicative Decrease: Set SSThresh (Cwin / 2) and Cwin = 1
                SendWinQ->ssThresh = SendWinQ->cwin / 2;
                SendWinQ->cwin = 1;
                updateAdditiveAckNum(SendWinQ);
                SendWinQ->nextSendSeqNum = SendWinQ->oldestSeqNum;
            }
            goto sendAgain;
        }

        dupAcks = 0;

        // Receive ACKs
        while (1) {
            // Unmask alarm handler routine
            sigprocmask(SIG_UNBLOCK, &sigset, NULL);

            len = Read(connFd, (void *) &packet, DATAGRAM_SIZE);
            readPckt(&packet, len, NULL, &ackNum, &winSize, NULL);

            // Mask alarm handler routine
            sigprocmask(SIG_BLOCK, &sigset, NULL);

            // Update advertised window size
            SendWinQ->advertisedWin = winSize;

            if (ackNum == PROBE_ACK_NO) {
                printf(KYEL "\nProbe ACK Received =>  Advertised Win: %d\n" RESET, winSize);
                break;

            } else {
                printf("\nACK Received =>  ACK num: %d\t Advertised Win: %d\n", ackNum, winSize);

                if (SendWinQ->oldestSeqNum == ackNum) {
                    dupAcks++;
                    if (dupAcks == 3) {
                        printf(KRED "3 Duplicate ACKs received. Enabling Fast Retransmit.\n" RESET);
                        done = 0;

                        // Fast Recovery Mechanism: Set SSThresh and Cwin = (Cwin / 2)
                        SendWinQ->ssThresh = SendWinQ->cwin / 2;
                        SendWinQ->cwin = max(SendWinQ->ssThresh, 1);
                        updateAdditiveAckNum(SendWinQ);
                        SendWinQ->nextSendSeqNum = SendWinQ->oldestSeqNum;
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

                        // Slow Start
                        incrementCwin(SendWinQ, 0);
                    }

                    if (IS_ADDITIVE_INC(SendWinQ)) {
                        if (SendWinQ->additiveAckNum == 0) {
                            updateAdditiveAckNum(SendWinQ);

                        } else if (SendWinQ->additiveAckNum <= SendWinQ->oldestSeqNum) {
                            // Additive Increase
                            incrementCwin(SendWinQ, 1);
                            updateAdditiveAckNum(SendWinQ);
                        }
                    }

                    // Update Sequence number to be sent next
                    if (SendWinQ->nextSendSeqNum < SendWinQ->oldestSeqNum)
                        SendWinQ->nextSendSeqNum = SendWinQ->oldestSeqNum;

                    printSendWindow(SendWinQ);

                    // No more packets to send. So receive all remaining ACKs.
                    if (done && (SendWinQ->oldestSeqNum != SendWinQ->nextNewSeqNum)) {
                        continue;
                    }
                    break;
                }
            }
        }

        setTimer(&timer, 0);
        // Unmask alarm handler routine
        sigprocmask(SIG_UNBLOCK, &sigset, NULL);
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
    } while (finAckPacket.ackNum != FIN_ACK_NO);

    setTimer(&timer, 0);
    printf(KGRN "Received\n" RESET);
    printf(RESET);
}

