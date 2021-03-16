#ifndef BEACON_H
#define BEACON_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "config.h"

#define UDP_BUFFER_SIZE                             1024
#define UDP_DEFAULT_BCAST_ENABLED                   1
#define UDP_DEFAULT_BCAST_PORT                      7123
#define UDP_DEFAULT_BCAST_ADVERTISING_INTERVAL_SEC  1

char udp_buff[UDP_BUFFER_SIZE];

typedef struct {
  int sock;
  int sinlen;
  struct sockaddr_in sock_in;
} UDP;

void udp_init(UDP *udp, DisConfig *cfg);
void start_beacon(UDP *udp, DisConfig *cfg);
void udp_close(UDP *udp);
void clear_buffer(char *buffer, int buffer_size);

#endif