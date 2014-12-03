#include "arp.h"

static ARPCache arpCache[100];
static int cacheEntries = 0;

ARPCache* searchARPCache(IA ipAddr) {
    int i;
    for (i = 0; i < cacheEntries; i++) {
        if (arpCache[i].isValid && (isSameIPAddr(arpCache[i].ipAddr, ipAddr))) {
            return &arpCache[i]; 
        }
    }
    return NULL;
}

bool updateARPCache(IA ipAddr, char *hwAddr, uint16_t ifindex, uint16_t hatype,
                    uint32_t connfd, bool forceUpdate)
{
    int i, updateInd;

    updateInd = cacheEntries;
    for (i = 0; i < cacheEntries; i++) {
        if (arpCache[i].isValid) {
            if (isSameIPAddr(arpCache[i].ipAddr, ipAddr)) {
                updateInd = i;
                break;
            }
        } else {
            if (forceUpdate)
                updateInd = i;
        }
    }

    if (forceUpdate || (updateInd != cacheEntries)) {
        // Update Cache Entry
        arpCache[updateInd].isValid = TRUE;
        arpCache[updateInd].ipAddr = ipAddr;
        arpCache[updateInd].ifindex = ifindex;
        arpCache[updateInd].hatype = hatype;
        arpCache[updateInd].connfd = connfd;
        if (hwAddr) {
            memcpy(arpCache[updateInd].hwAddr, hwAddr, IF_HADDR);
        }

        if (updateInd == cacheEntries) {
            cacheEntries++;
        }
        return TRUE;
    }

    return FALSE;
}
