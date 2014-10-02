#include "unp.h"

void sig_child(int signo) {
    wait(NULL);
    return;
}

int main(int argc, char **argv) {
    struct hostent *hostInfo;
    char hostAddr[INET_ADDRSTRLEN];
    int pipefd[2];

    if (argc != 2) {
        err_quit("usage: \"client <IPAddress/HostName>\"");
    }

    //TODO: Properly verify server hostname/hostaddr user option
    if (isdigit(argv[1][0])) {
        struct in_addr ipInfo;
        if (inet_pton(AF_INET, argv[1], &ipInfo) <= 0) {
            err_quit("inet_pton error for %s", argv[1]);
        }
        if ((hostInfo = gethostbyaddr(&ipInfo, sizeof(ipInfo), AF_INET)) == NULL) {
            err_quit("invalid server host address - %s", argv[1]);
        }
        strcpy(hostAddr, argv[1]);
    } else {
        if ((hostInfo = gethostbyname(argv[1])) == NULL) {
            err_quit("invalid server host name - %s", argv[1]);
        }
        if (inet_ntop(AF_INET, hostInfo->h_addr, hostAddr, INET_ADDRSTRLEN) <= 0) {
            err_quit("inet_ntop error for %s", argv[1]);
        }
    }
    // Valid hostName/hostAddr found
    printf("The server host is -> %s (%s)\n", hostInfo->h_name, hostAddr);

    Signal(SIGCHLD, sig_child);

    while (1) {
        int serviceOption, pid;

        while(1) {
            printf("\nEnter your service option:\n");
            printf("1. Echo Service\n");
            printf("2. Time Service\n");
            printf("3. Exit\n");
            if (scanf("%d", &serviceOption) != 1) {
                err_quit("Invalid input!");
            }
            if (serviceOption < 2 || serviceOption > 3) {
                err_msg("Invalid option!");
            } else {
                // Correct option entered
                break;
            }
        }

        if (serviceOption == 3) {
            printf("Thank you!\n");
            return 0;
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
            close(pipefd[0]);
            sprintf(writefd, "%d", pipefd[1]);

            if (serviceOption == 1) {
                execlp("xterm", "xterm", "-e", "./time_cli", hostAddr, writefd,  (char *) 0);
            } else {
                execlp("xterm", "xterm", "-e", "./time_cli", hostAddr, writefd,  (char *) 0);
            }
        } else {
            // parent process
            int n, maxfd;
            fd_set readfds;

            close(pipefd[1]);
            maxfd = pipefd[0] + 1;
            FD_ZERO(&readfds);
            while (1) {
                char recvBuf[MAXLINE];
                int len;

                FD_SET(fileno(stdin), &readfds);
                FD_SET(pipefd[0], &readfds);
                if (select(maxfd, &readfds, NULL, NULL, NULL) < 0) {
                    err_sys("select error on connection socket");
                }
                
                if (FD_ISSET(fileno(stdin), &readfds)) {
                    Fgets(recvBuf, MAXLINE, stdin);
                    err_msg("You are trying to interact with parent process." 
                            "Please interact with child process");
                }
                if (FD_ISSET(pipefd[0], &readfds)) {
                    if ((len = read(pipefd[0], recvBuf, MAXLINE)) > 0) {
                        recvBuf[len] = 0;       /* null terminate */
                        if (fputs(recvBuf, stdout) == EOF) {
                            err_sys("fputs stdout error");
                        }
                        // TODO: terminate if server crashes
                        break;
                    }
                }
            }
            close(pipefd[0]);
        }
    }
    return 0;
}

