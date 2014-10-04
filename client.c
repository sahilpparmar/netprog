#include "unp.h"

static void sig_child(int signo) {
    wait(NULL);
    return;
}

static struct hostent* getHostInfoByNameOrAddr(char *host, char *hostAddr) {
    struct hostent *hostInfo = NULL;
    struct in_addr ipInfo;

    if (inet_pton(AF_INET, host, &ipInfo) > 0) {
        hostInfo = gethostbyaddr(&ipInfo, sizeof(ipInfo), AF_INET);
    } else {
        hostInfo = gethostbyname(host);
    }
    if (hostInfo != NULL) {
        if (inet_ntop(AF_INET, hostInfo->h_addr, hostAddr, INET_ADDRSTRLEN) > 0) {
            return hostInfo;
       }
    }
    // No valid hostname/ipaddress found
    return NULL;
}

int main(int argc, char **argv) {
    struct hostent *hostInfo;
    char hostAddr[INET_ADDRSTRLEN] = "";

    if (argc != 2) {
        err_quit("usage: \"client <IPAddress/HostName>\"");
    }

    if ((hostInfo = getHostInfoByNameOrAddr(argv[1], hostAddr)) == NULL) {
        err_quit("Invalid Server HostName/IPAddress - %s", argv[1]);
    }

    // Valid hostName/hostAddr found
    printf("The server host is -> %s (%s)\n", hostInfo->h_name, hostAddr);

    Signal(SIGCHLD, sig_child);

    while (1) {
        int serviceOption, pid;
        int pipefd[2];

        while(1) {
            printf("\nServices\n");
            printf("===============\n");
            printf("1. Echo Service\n");
            printf("2. Time Service\n");
            printf("3. Exit\n");
            printf("Enter your option: ");

            if (scanf("%d", &serviceOption) != 1) {
                // invalid option
                char dummyBuf[MAXLINE];
                Fgets(dummyBuf, MAXLINE, stdin);
            } else if (serviceOption == 1 || serviceOption == 2) {
                // echo/time service requested
                break;
            } else if (serviceOption == 3) {
                // client exit
                printf("\nThank you!\n");
                return 0;
            }
            err_msg("\nInvalid option!");
        }

        if (pipe(pipefd) == -1) {
            err_sys("pipe creation failed");
        }

        if ((pid = fork()) < 0) {
            err_sys("child process creation failed");
        }

        if (pid == 0) {
            // child process
            char writefd[5];
            Close(pipefd[0]);
            snprintf(writefd, 5, "%d", pipefd[1]);

            if (serviceOption == 1) {
                execlp("xterm", "xterm", "-e", "./echo_cli", hostAddr, writefd,  (char *) 0);
            } else {
                execlp("xterm", "xterm", "-e", "./time_cli", hostAddr, writefd,  (char *) 0);
            }
        } else {
            // parent process
            int n, maxfd;
            fd_set readfds;

            Close(pipefd[1]);
            maxfd = pipefd[0] + 1;
            FD_ZERO(&readfds);
            while (1) {
                char recvBuf[MAXLINE];
                int len;

                FD_SET(fileno(stdin), &readfds);
                FD_SET(pipefd[0], &readfds);
                if (select(maxfd, &readfds, NULL, NULL, NULL) < 0) {
                    if (errno == EINTR) {
                        err_msg("\nClient termination due to errno = %s", strerror(errno));
                        break;
                    } else {
                        err_sys("select error on stdin and pipefd");
                    }
                }
                
                if (FD_ISSET(fileno(stdin), &readfds)) {
                    Fgets(recvBuf, MAXLINE, stdin);
                    err_msg("You are trying to interact with parent process." 
                            "Please interact with child process");
                }
                if (FD_ISSET(pipefd[0], &readfds)) {
                    if ((len = read(pipefd[0], recvBuf, MAXLINE)) > 0) {
                        recvBuf[len] = '\0';
                        if (fputs(recvBuf, stdout) == EOF) {
                            err_sys("fputs stdout error");
                        }
                        break;
                    }
                }
            }
            Close(pipefd[0]);
        }
    }
    return 0;
}

