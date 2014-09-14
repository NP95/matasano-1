#include "../include/httpget.h"

int http_request(unsigned char *response, unsigned char *host, unsigned char *page)
{
  struct sockaddr_in *remote;
  int sock;
  int tmpres;
  char *ip;
  char *get;
  char buf[BUFSIZ+1];

  sock = create_tcp_socket();
  if((ip = get_ip(host))==NULL)
	  return -1;
//   fprintf(stderr, "IP is %s\n", ip); 
  remote = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));
  remote->sin_family = AF_INET;
  tmpres = inet_pton(AF_INET, ip, (void *)(&(remote->sin_addr.s_addr)));
  if(tmpres < 0)
  {
    perror("Can't set remote->sin_addr.s_addr");
    return -1;
  }else if(tmpres == 0)
  {
    fprintf(stderr, "%s is not a valid IP address\n", ip);
    return -1;
  }
  remote->sin_port = htons(PORT);

  if(connect(sock, (struct sockaddr *)remote, sizeof(struct sockaddr)) < 0){
	return -1;
  }
  get = build_get_query(host, page);
//   fprintf(stderr, "Query is:\n<<START>>\n%s<<END>>\n", get);

  //Send the query to the server
  int sent = 0;
  while(sent < strlen(get))
  { 
    tmpres = send(sock, get+sent, strlen(get)-sent, 0);
    if(tmpres == -1){
	free(ip);
	free(remote);
	close(sock);
	return -1;
    }
    sent += tmpres;
  }
  //now it is time to receive the page
  memset(buf, 0, sizeof(buf));
  int htmlstart = 0;
  char * htmlcontent;
  unsigned int read = 0;
  while((tmpres = recv(sock, buf, BUFSIZ, 0)) > 0){
	memcpy(response+read, buf, tmpres);
	memset(buf, 0, tmpres);
	read += tmpres;
  }

  free(get);
  free(remote);
  free(ip);
  close(sock);

  if(tmpres < 0)
	  return tmpres;

  return read;
}

int create_tcp_socket()
{
  int sock;
  if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
    perror("Can't create TCP socket");
    return -1;
  }
  return sock;
}

char *get_ip(char *host)
{
  struct hostent *hent;
  int iplen = 15; //XXX.XXX.XXX.XXX
  char *ip = (char *)malloc(iplen+1);
  memset(ip, 0, iplen+1);
  if((hent = gethostbyname(host)) == NULL)
  {
    herror("Can't get IP");
    free(ip);
    return NULL;
  }
  if(inet_ntop(AF_INET, (void *)hent->h_addr_list[0], ip, iplen) == NULL)
  {
    perror("Can't resolve host");
    free(ip);
    return NULL;
  }
  return ip;
}

char *build_get_query(char *host, char *page)
{
  char *query;
  char *getpage = page;
  char *tpl = "GET /%s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n";
  if(getpage[0] == '/'){
    getpage = getpage + 1;
    fprintf(stderr,"Removing leading \"/\", converting %s to %s\n", page, getpage);
  }
  // -5 is to consider the %s %s %s in tpl and the ending \0
  query = (char *)malloc(strlen(host)+strlen(getpage)+strlen(USERAGENT)+strlen(tpl)-5);
  sprintf(query, tpl, getpage, host, USERAGENT);
  return query;
}

