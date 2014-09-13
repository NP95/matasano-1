#ifndef _HTMLGET_H
#define _HTMLGET_H

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>
int create_tcp_socket();
char *get_ip(char *host);
char *build_get_query(char *host, char *page);
void usage();

#define HOST "localhost"
#define PAGE "/"
#define PORT 3000
#define USERAGENT "HTMLGET 1.0"

#endif
