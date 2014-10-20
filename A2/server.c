#include "server.h"

int PORT_NO, WINDOW_SIZE;
struct client_request *Head = NULL;

static void sig_child(int signo)  // Remove child entry from the linkedlist
{
    int pid = wait(NULL);
    printf("Child with Pid : %d\n", pid);
    struct client_request *node = Head;
    struct client_request *prev = Head;

    while(node != NULL)
    {
        if(node->childpid == pid)
        {// remove this entry
            if (Head == node)
                Head = node->next;
            else
            {
                prev = node->next;
            }

            free(node);
            return;
        }
        prev = node;
        node = node->next;
    }

    printf("ERROR!! Unable to find a record for child with pid:%d \n",pid);
    return;
}

int main() 
{
   // Signal(SIGCHLD,sig_child); // UNCOMMENT LATER
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
                    int ret = search_add_client_request(cliaddr, sockfd, i, totalIP);
                    if (ret > 0)
                        break;
                    else if (ret <0)
                    {
                        printf("Error detected!\n");
                        break;
                    }
//                    printf("Data Read: %s \n",mesg);

                    // Fork a child and pass IP address
                    
                } //end if

            } //end for
            
        } // end While
}

// Maintain a structure that keeps track of requests coming from clients
// client_request structure maintains the client IP address, client port number 
// for each request that it encounters. It also stores the Child Pid 
// return Child processid for new Requests
// return 0 for duplicate requests
// return -1 for Error
int search_add_client_request(struct sockaddr_in cliaddr, int *sock_fd, int req_sock, int total_IP)
{
    struct client_request *node = Head;
    while(node != NULL) // Check if it is a duplicate request
    {
        if(compare_address(&(node->cliaddr), &cliaddr) == 0)
        {
            return node->childpid;
        }
        node = node->next;
    }
    // Create a node if the entry is not present
    struct client_request *new_node = malloc(sizeof(struct client_request));
    int pid;
    new_node->cliaddr = cliaddr;
    new_node->next = Head;
    Head = new_node; // update head node

    if ((pid = fork()) < 0)
    {
        perror("fork failed\n");
        return(-1);
    }
    
    if (pid == 0)// Child process
    {
        /* Child would close all the socket descriptor except one
         * Next it would create a new socket and send a second handshake
         * to the client with the new socket in the payload.
         * It would also start a new timer for the second handshake 
         */
        int i;
        // Close all the sockets except the one where request arrived
        for (i = 0; i < total_IP; i++ ) 
        {
            if (i != req_sock)
                close(sock_fd[i]);
        }

        //printf("This is the Child process\n");


        //------------------ Second Handshake ------------------------
        // create a new socked and connect with the client and bind to it
/*        int child_socfd;
        struct sockaddr_in child_cliaddr, child_servaddr;
           if (getsockname(sock_fd[req_sock],(SA *) &child_servaddr, sizeof(struct sockaddr)) == -1) {
                     perror("getsockname() failed");
                           return -1;
            }
            printf("Server IP address is: %s\n", inet_ntoa(child_servaddr.sin_addr));
            printf("Local port is: %d\n\n", (int) ntohs(child_servaddr.sin_port));

        //After third acknowledgement
*/
        exit(0);
        //close(sock_fd[req_sock]);
    }
    else // Parent process: It would simply store the processId and return the id
    {
        new_node->childpid = pid;
        printf("New Request Added with child Id: %d\n", pid);
        printf("New request from client: %s\n", Sock_ntop((SA *)&(new_node->cliaddr), sizeof(struct sockaddr_in)));
        return pid;
    }
}

int compare_address(struct sockaddr_in *prev_req, struct sockaddr_in *new_req)
{
    if((prev_req->sin_addr.s_addr != new_req->sin_addr.s_addr) ||  // Check the IP Address
            (prev_req->sin_port != new_req->sin_port) ||  // Check the Port Number
            (prev_req->sin_family != new_req->sin_family)) // Check the Address family
    {
        //printf("New request from client: %s\n", Sock_ntop((SA *)new_req, sizeof(struct sockaddr_in)));
        return 1; // New Request
    }
    else
    {
//        printf("Repeated request from client %s", Sock_ntop((SA *)&new_req, sizeof(struct sockaddr_in)));
        return 0; // Repeated Request
    }
}
