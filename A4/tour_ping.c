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

static char* getHWAddrByIPAddr(IA s_ipaddr, char *s_haddr) {
    HWAddr hwAddr;
    struct sockaddr_in sockAddr;

    bzero(&sockAddr, sizeof(sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr   = s_ipaddr;
    sockAddr.sin_port   = 0;

    bzero(&hwAddr, sizeof(hwAddr));
    hwAddr.sll_ifindex = 2;
    hwAddr.sll_hatype  = ARPHRD_ETHER;
    hwAddr.sll_halen   = ETH_ALEN;

    if (areq((SA *) &sockAddr, sizeof(sockAddr), &hwAddr) == 0) {
        memcpy(s_haddr, hwAddr.sll_addr, ETH_ALEN);
        return s_haddr;
    }
    return NULL;
}

static void printPingPacket(PingPacket *packet) {
    struct ip *iphdr = &packet->pingIPPacket.iphead;
    struct icmp *icmp = &packet->pingIPPacket.icmphead;

    printf("Ethernet Header =>\n");
    printf ("Destination MAC: %s\n", ethAddrNtoP(packet->destMAC));
    printf ("Source MAC: %s\n", ethAddrNtoP(packet->srcMAC));
    printf("Protocol Number: 0x%x\n", ntohs(packet->protocol));

    printf("IP Header =>\n");
    printf("Header Len: %d\t", iphdr->ip_hl);
    printf("Version: %d\t", iphdr->ip_v);
    printf("TOS: %d\n", iphdr->ip_tos);
    printf("Total Len: %d\t", ntohs(iphdr->ip_len));
    printf("Ident Num: 0x%x\n", ntohs(iphdr->ip_id));
    printf("Offset: %d\t", iphdr->ip_off);
    printf("TTL: %d\t", iphdr->ip_ttl);
    printf("Protocol Num: %d\n", iphdr->ip_p);
    printf("Src IP: %s\t", getIPStrByIPAddr(iphdr->ip_src));
    printf("Dst IP: %s\t", getIPStrByIPAddr(iphdr->ip_dst));
    printf("Checksum: 0x%x\n", iphdr->ip_sum);

    printf("ICMP Header =>\n");
    printf("Type: %d\t", icmp->icmp_type);
    printf("Code: %d\t", icmp->icmp_code);
    printf("Checksum: 0x%x\n", icmp->icmp_cksum);
    printf("ID: 0x%x\t", ntohs(icmp->icmp_id));
    printf("Seq: %d\t", ntohs(icmp->icmp_seq));
    printf("Data: %s\n", icmp->icmp_data);
}

static void fillPingIPHeader(PingIPPacket *packet, IA hostIP, IA destIP) {
    struct ip *iphdr = (struct ip*) &packet->iphead;
    iphdr->ip_hl  = sizeof(struct ip) >> 2;
    iphdr->ip_v   = IPVERSION;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons(sizeof(PingIPPacket));
    iphdr->ip_id  = htons(PING_REQ_ID);
    iphdr->ip_off = 0;
    iphdr->ip_ttl = 64;
    iphdr->ip_p   = IPPROTO_ICMP;
    iphdr->ip_src = hostIP;
    iphdr->ip_dst = destIP;
    iphdr->ip_sum = in_cksum((uint16_t *)packet, sizeof(PingIPPacket));
}

static void fillICMPEchoPacket(struct icmp *icmp) {
    static int nsent = 0;

    icmp->icmp_type  = ICMP_ECHO;
    icmp->icmp_code  = 0;
    icmp->icmp_id    = htons(PING_REQ_ID);
    icmp->icmp_seq   = htons(++nsent);
    Gettimeofday((struct timeval *) icmp->icmp_data, NULL);

    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum((uint16_t *) icmp, sizeof(struct icmp));
}

static bool sendPingPacket(int sockfd, int destVMNode, IA hostIP, char *hostMAC) {
    PingPacket packet;
    struct sockaddr_ll sockAddr;
    IA destIP;
    char destMAC[IF_HADDR];

    destIP = getIPAddrByVmNode(destVMNode);
    if (getHWAddrByIPAddr(destIP, destMAC) == NULL) {
        err_msg("Disable Pinging due to AREQ timeout");
        return FALSE;
    }

    bzero(&packet, sizeof(packet));
    bzero(&sockAddr, sizeof(&sockAddr));

    // Fill ICMP header
    fillICMPEchoPacket(&packet.pingIPPacket.icmphead);

    // Fill IP header
    fillPingIPHeader(&packet.pingIPPacket, hostIP, destIP);

    // Fill Ethernet header
    memcpy(packet.destMAC, destMAC, IF_HADDR);
    memcpy(packet.srcMAC,  hostMAC, IF_HADDR);
    packet.protocol = htons(ETH_P_IP);

    // Fill sockAddr
    sockAddr.sll_family   = PF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_IP);
    sockAddr.sll_hatype   = ARPHRD_ETHER;
    sockAddr.sll_pkttype  = PACKET_OTHERHOST;
    sockAddr.sll_halen    = ETH_ALEN;
    sockAddr.sll_ifindex  = 2;
    memcpy(sockAddr.sll_addr, destMAC, ETH_ALEN);
 
    // Send PING Request
#if DEBUG
    printf("Sending a PING packet to VM%d\n", destVMNode);
    printPingPacket(&packet);
#endif
    Sendto(sockfd, (void *) &packet, sizeof(packet), 0, (SA *) &sockAddr, sizeof(sockAddr));

    return TRUE;
} 

int sendPingRequests(int sockfd, bool *pingStatus, IA hostIP,
                    char *hostMAC, int specific)
{
    if (specific != -1) {
        assert(pingStatus[specific] && "Ping Status should be enable");
        if (!sendPingPacket(sockfd, specific, hostIP, hostMAC))
            pingStatus[specific] = FALSE;
    } else {
        int i;
        for (i = 1; i <= MAX_NODES; i++) {
            if (pingStatus[i]) {
                if (!sendPingPacket(sockfd, i, hostIP, hostMAC))
                    pingStatus[i] = FALSE;
            }
        }
    }
}

bool recvPingReply(int sockfd) {
    PingIPPacket packet;
    double rtt;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend, *tvrecv, tval;
    int iplen, icmplen, nbytes;
    
    Gettimeofday(&tval, NULL);
    tvrecv = &tval;

    nbytes = Recvfrom(sockfd, &packet, sizeof(packet), 0, NULL, NULL);
#if DEBUG
    printf("Receiving PING Reply\n");
#endif
    ip   = &packet.iphead;
    icmp = &packet.icmphead;

    iplen = ip->ip_hl << 2;
    /* malformed packet */
    if ((icmplen = nbytes - iplen) < 8)
        return FALSE;
    /* not a response to our ECHO_REQUEST */
    if (ntohs(icmp->icmp_id) != PING_REQ_ID)
        return FALSE;
    /* not enough data to use */
    if (icmplen < 16)
        return FALSE;

    tvsend = (struct timeval *) icmp->icmp_data;
    tv_sub(tvrecv, tvsend);
    rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

    printf("\n%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
            icmplen, getIPStrByIPAddr(ip->ip_src),
            ntohs(icmp->icmp_seq), ip->ip_ttl, rtt);

    return TRUE;
}

