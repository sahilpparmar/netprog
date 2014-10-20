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
    char data[MAXLINE];
    getParam(inp_file, data, MAXLINE);
    PORT_NO = atoi(data);
    getParam(inp_file, data, MAXLINE);
    WINDOW_SIZE = atoi(data);

    //if((PORT_NO = atoi(getParam(inp_file, data, MAXLINE))) == 0)
    //{
    //    printf("Port number not set correctly\n");
    //    exit(0);
    //}
    //if((WINDOW_SIZE = atoi(getParam(inp_file, data, MAXLINE))) == 0)
    //{
    //    printf("Window Size not set correctly\n");
    //    exit(0);
    //}
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
    int totalIP = print_ifi_info_plus(get_ifi_info_plus(family, doaliases));
    printf("Total number of IP addresses: %d\n", totalIP);

    int *sockfd;
    struct sockaddr_in servaddr, cliaddr;
    int counter = 0;

    sockfd = (int *)malloc(totalIP * sizeof(int));

    for (ifihead = ifi = get_ifi_info_plus(family, doaliases);
             ifi != NULL; ifi = ifi->ifi_next) {

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
        char message[MAXLINE];
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
                    n = Recvfrom(sockfd[i], message, MAXLINE, 0, (SA *)&cliaddr, &len);
                    // Read and print the child IP address
//                    printf("Connection request from %s \n", Sock_ntop((SA *)&cliaddr, len));
                    message[n] = '\0';
                    printf("\nNew Incoming Client Connection!\n");
                    printf("FileName: %s \n",message);
                    int ret = search_add_client_request(cliaddr, sockfd, i, totalIP);
                    if (ret > 0)
                        break;
                    else if (ret <0)
                    {
                        printf("Error detected!\n");
                        break;
                    }

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
                Close(sock_fd[i]);
        }

        //printf("This is the Child process\n");


        //------------------ Second Handshake ------------------------
        // create a new socked and connect with the client and bind to it
        int len, connFd, newChildPortNo;
        struct sockaddr_in child_cliaddr, child_servaddr;

        len = sizeof(struct sockaddr_in);
        Getsockname(sock_fd[req_sock],(SA *) &child_servaddr, &len);

        printf("Server IP address is: %s\n", inet_ntoa(child_servaddr.sin_addr));
        printf("Local port is: %d\n", (int) ntohs(child_servaddr.sin_port));

        // Create a new connection socket
        connFd = Socket(AF_INET, SOCK_DGRAM, 0);

        child_servaddr.sin_port = 0; // Choose a new port number
        Bind(connFd, (SA *)&child_servaddr, sizeof(child_servaddr));

        Getsockname(connFd,(SA *) &child_servaddr, &len);
        newChildPortNo = ntohs(child_servaddr.sin_port);
        printf("New Conn Port No : %d\n", newChildPortNo); 
        Connect(connFd, (SA *) &cliaddr, sizeof(cliaddr));

        char message[MAXLINE];
        sprintf(message, "%d", newChildPortNo);
        Sendto(sock_fd[req_sock], message, strlen(message), 0, (SA *) &cliaddr, sizeof(cliaddr));

        Close(sock_fd[req_sock]);
        
        //After third acknowledgement
        len = Read(connFd, message, MAXLINE);
        message[len] = '\0';
        printf("Third ACK : %s\n", message);
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
