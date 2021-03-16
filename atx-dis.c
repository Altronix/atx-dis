#include <stdio.h>
#include <pthread.h>
#include "log.h"
#include "config.h"
#include "beacon.h"
#include "watch.h"

int main(int argc, char*argv[])
{
  log_info("Starting atx-dis...\n");
  UDP udp;
  DisConfig cfg;
  pthread_t td;

  cfg_init(&cfg);
  pthread_create(&td, NULL, threadWatch, (void *)(&cfg));
  pthread_detach(td);

  udp_init(&udp, &cfg);
  start_beacon(&udp, &cfg);
}

