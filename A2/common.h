#ifndef _COMMON_H
#define _COMMON_H

#define SERVER_IN   "server.in"
#define CLIENT_IN   "client.in"
#define PARAM_SIZE  100

char* getStringParamValue(FILE *inp_file, char *paramVal);
int getIntParamValue(FILE *inp_file);
float getFloatParamValue(FILE *inp_file);

int print_ifi_info_plus(struct ifi_info *ifihead);

#endif /* !_COMMON_H */
