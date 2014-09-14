#ifndef _HTMLGET_H
#define _HTMLGET_H

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

int http_request(unsigned char *response, unsigned char *host, unsigned char *page);
int create_tcp_socket(void);
char *get_ip(char *host);
char *build_get_query(char *host, char *page);

#define HOST "localhost"
#define PAGE "/"
#define PORT 3000
#define USERAGENT "HTMLGET 1.0"

#endif
