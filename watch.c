#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include "log.h"
#include "config.h"
#include "watch.h"

#define EVENT_SIZE      (sizeof (struct inotify_event))
#define BUF_LEN         (1024 * (EVENT_SIZE + 64))

/*
  Inotify Thread
*/
void *threadWatch(void *obj)
{
  log_info("Starting files watch thread...\n");

  int fd;
  fd = inotify_init();
  if (fd < 0)
    perror("inotify_init()");

  int wd;
  wd = inotify_add_watch(fd, DIRECTORY_TO_WATCH, IN_MODIFY);
  if (wd < 0)
    perror("inotify_add_watch");

  char buf[BUF_LEN];
  int len;

  while(1)
  {
    len = read(fd, buf, BUF_LEN);

    if (len > 0)
    {
      int i = 0;
      while (i < len)
      {
        struct inotify_event *event;
        event = (struct inotify_event *) &buf[i];

        if (event->mask & IN_MODIFY)
        {
          if (strcmp(event->name, ATX_DIS_CONFIG_FILENAME) == 0)
          {
            log_info("File modified: %s \n", event->name);
            read_cfg_file((DisConfig*)obj);
          }
          if (strcmp(event->name, ATX_SYS_CONFIG_FILENAME) == 0)
          {
            log_info("File modified: %s \n", event->name);
            read_sys_file((DisConfig*)obj);
          }
          if (strcmp(event->name, ATX_LINQD_CONFIG_FILENAME) == 0)
          {
            log_info("File modified: %s \n", event->name);
            read_linqd_file((DisConfig*)obj);
          }
        }

        i += EVENT_SIZE + event->len;
      }
    }
  }
  
}