#include "arp.h"

static ARPCache arpCache[100];
static int cacheEntries = 0;

static void printARPCache() {
    int i;

    printf("============================================================================\n");
    printf("|       IP Addr      |         MAC Addr        | IfIndex | HAType | Connfd |\n");
    printf("============================================================================\n");
    for (i = 0; i < cacheEntries; i++) {
        if (arpCache[i].isValid) {
            printf("| %18s | %23s | %7d | %6d | %6d |\n",
                getIPStrByIPAddr(arpCache[i].ipAddr),
                ethAddrNtoP(arpCache[i].hwAddr),
                arpCache[i].ifindex,
                arpCache[i].hatype,
                arpCache[i].connfd);
        }
    }
    printf("============================================================================\n");

}

ARPCache* searchARPCache(IA ipAddr) {
    int i;
    for (i = 0; i < cacheEntries; i++) {
        if (arpCache[i].isValid && (isSameIPAddr(arpCache[i].ipAddr, ipAddr))) {
            return &arpCache[i]; 
        }
    }
    return NULL;
}

void invalidateCache(IA ipAddr) {
    ARPCache *entry = searchARPCache(ipAddr);
    assert(entry != NULL && "Invalid cache entry to invalidate");
    entry->isValid = FALSE;

    printf("Invalidating Cache Entry with IP %s\n", getIPStrByIPAddr(ipAddr));
    printARPCache();
}

bool updateARPCache(IA ipAddr, char *hwAddr, int ifindex, uint8_t hatype,
                    int connfd, bool forceUpdate)
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
        arpCache[updateInd].ipAddr  = ipAddr;
        arpCache[updateInd].ifindex = ifindex;
        arpCache[updateInd].hatype  = hatype;
        arpCache[updateInd].connfd  = connfd;
        if (hwAddr) {
            memcpy(arpCache[updateInd].hwAddr, hwAddr, IF_HADDR);
        }

        if (updateInd == cacheEntries) {
            cacheEntries++;
        }

        printf("Updating Cache Entry with IP %s\n", getIPStrByIPAddr(ipAddr));
        printARPCache();

        return TRUE;
    }

    return FALSE;
}

