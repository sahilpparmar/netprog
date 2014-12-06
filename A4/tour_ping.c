#include "tour.h"

bool isPingEnable(bool *pingStatus) {
    int i;
    for (i = 1; i <= MAX_NODES; i++) {
        if (pingStatus[i])
            return TRUE;
    }
    return FALSE;
}

void disablePingStatus(bool *pingStatus) {
    int i;
    for (i = 1; i <= MAX_NODES; i++) {
        pingStatus[i] = FALSE;
    }
}

int sendPingRequests(bool *pingStatus, int specific) {
    // TODO: Get MAC for source IP via areq and send a PING REQ
    if (specific != -1) {
        assert(pingStatus[specific] && "Ping Status should be enable");
        printf("Sending a PING packet to VM%d\n", specific);
    } else {
        int i;
        for (i = 1; i <= MAX_NODES; i++) {
            if (pingStatus[i])
                printf("Sending a PING packet to VM%d\n", i);
        }
    }
}

