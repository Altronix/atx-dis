#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h> 
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "log.h"
#include "config.h"
#include "beacon.h"

extern pthread_mutex_t mux;

/*
  Init UDP socket
*/
void udp_init(UDP *udp, DisConfig *cfg)
{
  int bcast_enabled = 1;
  udp->sinlen = sizeof(struct sockaddr_in);

  memset(&(udp->sock_in), 0, udp->sinlen);
  udp->sock = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  udp->sock_in.sin_addr.s_addr = htonl(INADDR_ANY);
  udp->sock_in.sin_port = htons(0);
  udp->sock_in.sin_family = PF_INET;

  int status = bind(udp->sock, (struct sockaddr *)&(udp->sock_in), udp->sinlen);
  log_debug("Bind Status = %d", status);

  status = setsockopt(udp->sock, SOL_SOCKET, SO_BROADCAST, &bcast_enabled, sizeof(int) );
  log_debug("Setsockopt Status = %d", status);

  udp->sock_in.sin_addr.s_addr=htonl(-1); // Broadcast
  udp->sock_in.sin_port = htons(cfg->dis); 
  udp->sock_in.sin_family = PF_INET;
}

/*
  Start Discovery Beacon
*/
void start_beacon(UDP *udp, DisConfig *cfg)
{
  while(1) {
    if(cfg->enable)
    {
      clear_buffer(udp_buff,UDP_BUFFER_SIZE);
      snprintf(udp_buff, UDP_BUFFER_SIZE, "{\"product\":\"%s\",\"id\":\"%s\",\"ip\":\"%s\",\"http\":%d,\"https\":%d}\n",cfg->product,cfg->id,cfg->ip,cfg->http,cfg->https);
      int status = sendto(udp->sock, udp_buff, strlen(udp_buff), 0, (struct sockaddr *)&(udp->sock_in), udp->sinlen);
      log_debug("UDP Bcast Status = %d", status);
      sleep(cfg->interval);
    }	
	}
}

/*
  Close udp socket
*/
void udp_close(UDP *udp)
{
  close(udp->sock);
}

/*
  Clear buffer
*/
void clear_buffer(char *buffer, int buffer_size)
{
  memset(buffer, 0, buffer_size*sizeof(buffer[0]));
}