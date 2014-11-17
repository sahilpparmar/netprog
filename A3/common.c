#include "common.h"

char canonicalIP[11][100] = {
                             "",
                             "130.245.156.21",
                             "130.245.156.22",
                             "130.245.156.23",
                             "130.245.156.24",
                             "130.245.156.25",
                             "130.245.156.26",
                             "130.245.156.27",
                             "130.245.156.28",
                             "130.245.156.29",
                             "130.245.156.20"
                            };

char* getFullPath(char *fullPath, char *fileName, int size, bool isTemp) {

    if (getcwd(fullPath, size) == NULL) {
        err_msg("Unable to get pwd via getcwd()");
    }

    strcat(fullPath, fileName);

    if (isTemp && mkstemp(fullPath) == -1) {
        err_msg("Unable to get temp file via mkstemp()");
    }

    Unlink(fullPath);

    return fullPath;
}

int getHostVmNodeNo() {
    char hostname[1024];
    int nodeNo;

    gethostname(hostname, 10);
    nodeNo = atoi(hostname+2);
    if (nodeNo < 1 || nodeNo > 10) {
        err_quit("Invalid hostname: %s", hostname);
    }
    return nodeNo;
}

