/***
 * common.c - contains common code between client and server
 *
 ***/

#include "unp.h"

char* getParam(FILE *fp, char *ptr, int n) {
    char line[MAXLINE], dummy[MAXLINE];

    if (fgets(line, n, fp) == NULL || strlen(line) == 0) {
        return NULL;
    }
    
    if (sscanf(line, "%s", ptr) > 0)
        return ptr;
    return NULL;
}
