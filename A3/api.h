#ifndef _API_H
#define _API_H

typedef struct api_data_t {
    char data[100];
    char canonicalIP[100];
    int port;
    int forceRediscovery;
} ApiData;

void msg_send(int sockfd, char *destIP, int destPort, char *msg, int forceRediscovery);
int msg_recv(int sockfd, char *msg, char *srcIP, int *srcPort);
void printApiData(ApiData *data);

#endif /* !_API_H */
