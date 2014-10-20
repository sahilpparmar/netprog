#include "server.h"

int PORT_NO, WINDOW_SIZE;
struct client_request *Head = NULL; 
int main() {

    initialize_params();
    get_all_interfaces();
    exit(0);

}

int initialize_params()
{
    FILE *inp_file = fopen(SERVER_IN, "r");

    if (inp_file == NULL) {
        err_quit("Unknown server argument file : '%s'\n", SERVER_IN);
    }


    char line[READ_BUFF];
    if(fgets(line, sizeof line, inp_file) != NULL) /* read a Port number*/
    {
        if(atoi(line) == 0)
        {
            printf("Port number not set correctly\n");
            exit(0);
        }
        printf("Port number read: %d\n", atoi(line));
        PORT_NO = atoi(line);
    }
    
    if(fgets(line, sizeof line, inp_file) != NULL) /* read a Port number*/
    {
        if(atoi(line) == 0)
        {
            printf("Window size not set correctly\n");
            exit(0);
        }
        printf("Window Size read: %d\n", atoi(line));
        WINDOW_SIZE = atoi(line);
    }
    Fclose(inp_file);
    
}

int get_all_interfaces()
{

    struct ifi_info *ifi, *ifihead;
    struct sockaddr *sa;
    u_char *ptr;
    int i, family, doaliases;
    family = AF_INET;

    doaliases = 1; // 1 or 0

    // Iterate over get_ifi_info_plus and count the total number of IP addresses
    int totalIP = 0;
    for (ifihead = ifi = get_ifi_info_plus(family, doaliases);
             ifi != NULL; ifi = ifi->ifi_next) {
        totalIP++;
    }
    printf("Total number of IP addresses: %d\n", totalIP);

    int *sockfd;
    struct sockaddr_in servaddr, cliaddr;
    int counter = 0;

    sockfd = (int *)malloc(totalIP * sizeof(int));

    for (ifihead = ifi = get_ifi_info_plus(family, doaliases);
             ifi != NULL; ifi = ifi->ifi_next) {
                printf("%s: ", ifi->ifi_name);
                if (ifi->ifi_index != 0)
                        printf("(%d) ", ifi->ifi_index);
                printf("<");
/* *INDENT-OFF* */
                if (ifi->ifi_flags & IFF_UP)                    printf("UP ");
                if (ifi->ifi_flags & IFF_BROADCAST)             printf("BCAST ");
                if (ifi->ifi_flags & IFF_MULTICAST)             printf("MCAST ");
                if (ifi->ifi_flags & IFF_LOOPBACK)              printf("LOOP ");
                if (ifi->ifi_flags & IFF_POINTOPOINT)   printf("P2P ");
                printf(">\n");
/* *INDENT-ON* */

                if ( (i = ifi->ifi_hlen) > 0) {
                        ptr = ifi->ifi_haddr;
                        do {
                                printf("%s%x", (i == ifi->ifi_hlen) ? "  " : ":", *ptr++);
                        } while (--i > 0);
                        printf("\n");
                }
                if (ifi->ifi_mtu != 0)
                        printf("  MTU: %d\n", ifi->ifi_mtu);

                if ( (sa = ifi->ifi_addr) != NULL)
                        printf("  IP addr: %s\n",
                                                Sock_ntop_host(sa, sizeof(*sa)));

/*=================== cse 533 Assignment 2 modifications ======================*/

                if ( (sa = ifi->ifi_ntmaddr) != NULL)
                        printf("  network mask: %s\n",
                                                Sock_ntop_host(sa, sizeof(*sa)));

                if ( (sa = ifi->ifi_brdaddr) != NULL)
                        printf("  broadcast addr: %s\n",
                                                Sock_ntop_host(sa, sizeof(*sa)));
                if ( (sa = ifi->ifi_dstaddr) != NULL)
                        printf("  destination addr: %s\n",
                                                Sock_ntop_host(sa, sizeof(*sa)));

                sockfd[counter] = Socket(AF_INET, SOCK_DGRAM, 0);
                bzero(&servaddr, sizeof(servaddr));
                //servaddr.sin_family = sa->sin_family;
//servaddr.sin_addr.s_addr = sa->sin_port;
                servaddr = *(struct sockaddr_in *)ifi->ifi_addr;
                servaddr.sin_port = htons(PORT_NO);
                Bind(sockfd[counter++], (SA *)&servaddr, sizeof(servaddr));
        }
        free_ifi_info_plus(ifihead);

        // Listen using select on all socket
        fd_set rset;
        FD_ZERO(&rset);
        int maxfd = sockfd[--counter] + 1;
        char mesg[MAXLINE];
        int n = 0;

        while(1)
        {
            for (i = 0 ; i < totalIP; i++)
                FD_SET(sockfd[i], &rset);

           // printf("Listening for connections\n");

            select(maxfd, &rset, NULL, NULL, NULL);

            //Check which Socket got packets
            for (i = 0 ; i < totalIP; i++)
            {
                if (FD_ISSET(sockfd[i], &rset))
                {
                    struct sockaddr_in cliaddr;
                    socklen_t len = sizeof(cliaddr);
                    n = Recvfrom(sockfd[i], mesg, MAXLINE, 0, (SA *)&cliaddr, &len);

                    // Read and print the child IP address
//                    printf("Connection request from %s \n", Sock_ntop((SA *)&cliaddr, len));
                    search_add_client_request(cliaddr);
//                    printf("Data Read: %s \n",mesg);
                    // Maintain a structure that keeps track of requests coming from clients
                    // Initialize the structure in the begining
                    // Create two functions
                    // Search and add =>
                    // remove =>
                    // structure has the client IP address, client port number and child Pid

                    // Fork a child and pass IP address
                    
                } //end if

            } //end for
            
        } // end While
}

int search_add_client_request(struct sockaddr_in cliaddr)
{
    // return processid if not present
    // return 0 if present
    // return -1 in case there is an error
    struct client_request *node = Head;
    while(node != NULL) // Check if header is present
    {
        if(compare_address(&(node->cliaddr), &cliaddr) == 0)
        {
            return node->childpid;
        }
        node = node->next;
    }
    // Create a node if head is not present
    struct client_request *new_node = malloc(sizeof(struct client_request));

    new_node->cliaddr = cliaddr;
    new_node->next = Head;
    //new-> pid = fork(); // fork logic
    Head = new_node;
    printf("New Request Added!!\n");
    //return new->pid;
    return 10;
}

int compare_address( struct sockaddr_in *prev_req, struct sockaddr_in *new_req)
{
    if((prev_req->sin_addr.s_addr != new_req->sin_addr.s_addr) || 
            (prev_req->sin_port != new_req->sin_port) || 
            (prev_req->sin_family != new_req->sin_family))
    {
        printf("New request from client: %s\n", Sock_ntop((SA *)&new_req, sizeof(struct sockaddr_in)));
        return -1;
    }
    else
    {
//        printf("Repeated request from client %s", Sock_ntop((SA *)&new_req, sizeof(struct sockaddr_in)));
        return 0;
    }
}
