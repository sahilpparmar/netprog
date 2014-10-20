#define SERVER_IN "server.in"
#define READ_BUFF 1024

#include "unp.h"
#include "unpifiplus.h"
#include <stdio.h>
int get_all_interfaces();
int initialize_params();


extern struct ifi_info *Get_ifi_info_plus(int family, int doaliases);
extern void free_ifi_info_plus(struct ifi_info *ifihead);

struct CONFIG{
    int PORT_NO;
    int WINDOW_SIZE;
};

struct client_request{
  struct sockaddr_in cliaddr;
  int childpid;
  struct client_request *next;
};
