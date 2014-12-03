#include "tour.h"

static IP HostIP;
static IP MulticastIP;
static uint16_t MulticastPort;
struct sockaddr_in GroupSock = 0;
int MulticastSD;

static void parseClientParams() {
    FILE *inp_file = fopen(CLIENT_IN, "r");

    // Read input parameters
    if (inp_file != NULL) {
        getStringParamValue(inp_file, MulticastIP);
        MulticastPort = getIntParamValue(inp_file);

        Fclose(inp_file);
    } else {
        err_quit("Unknown argument file: '%s'", CLIENT_IN);
    }
}

static void setMultiCast() {
	int reuse = 1;
	struct ip_mreq group;
	/* Enable SO_REUSEADDR to allow multiple instances of this */
	/* application to receive copies of the multicast datagrams. */
	if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0)
	{
		perror("Setting SO_REUSEADDR error");
		close(sd);
		exit(1);
	}
	else
		printf("Setting SO_REUSEADDR...OK.\n");

	/* Bind to the proper port number with the IP address */
	/* specified as INADDR_ANY. */
	memset((char *) &GroupSock, 0, sizeof(GroupSock));
	GroupSock.sin_family = AF_INET;
	GroupSock.sin_port = htons(4321); // 
	GroupSock.sin_addr.s_addr = INADDR_ANY;
	if(bind(sd, (struct sockaddr*)&GroupSock, sizeof(GroupSock)))
	{
		perror("Binding datagram socket error");
		close();
		exit(1);
	}
	else
		printf("Binding datagram socket...OK.\n");

	/* Join the multicast group 226.1.1.1 on the local 203.106.93.94 */
	/* interface. Note that this IP_ADD_MEMBERSHIP option must be */
	/* called for each local interface over which the multicast */
	/* datagrams are to be received. */
	group.imr_multiaddr.s_addr = inet_addr("226.1.1.1");
	group.imr_interface.s_addr = inet_addr("203.106.93.94");
	if(setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0)
	{
		perror("Adding multicast group error");
		close(sd);
		exit(1);
	}
	else
		printf("Adding multicast group...OK.\n");

	/* Read from the socket. */
	datalen = sizeof(databuf);
	if(read(sd, databuf, datalen) < 0)
	{
		perror("Reading datagram message error");
		close(sd);
		exit(1);
	}
	else
	{
		printf("Reading datagram message...OK.\n");
		printf("The message from multicast server is: \"%s\"\n", databuf);
	}
	return 0;
}




static void startTour(IP *IPList, int max) {
	printf("Initializing Tour\n");
}

static void startPassiveMode() {

}

static void readIP() {


}
static void createSockets() {
	/* Create a datagram socket on which to receive. */
	MulticastSD = socket(AF_INET, SOCK_DGRAM, 0);
	if(MulticastSD < 0)
	{
		perror("Opening datagram socket error");
		exit(1);
	}
	else
		printf("Opening datagram socket....OK.\n");
}
int main(int argc, char* argv[]) {

    IP IPList[MAXHOPS] = {0};
    int nodeNo = 0;
    int i;

    getIPByVmNode(HostIP, getHostVmNodeNo());
    printf("Tour module running on VM%d with IP:%s\n", getHostVmNodeNo(), HostIP);
    createSockets();

    if (argc == 1) {
        printf("No Tour specified\n");
        printf("Running in Listening Mode\n");
        startPassiveMode();

    } else {
        for (i = 1; i < argc; i++) {
            nodeNo = atoi(argv[i]+2);
            getIPByVmNode(IPList[i], nodeNo);
            printf("%d : VM%d ---> %s\n",i, nodeNo, IPList[i]);
        }
        memcpy((void *)IPList[0], (void *)HostIP, sizeof(HostIP));

        parseClientParams();
        if(multicastSock == 0)
        {
            setMultiCast();
        }
        startTour(IPList, i);
    }
}
