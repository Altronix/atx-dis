#ifndef CONFIG_H
#define CONFIG_H

#define ATX_DIS_CONFIG_FILENAME     "atx.config.dis.json"
#define ATX_SYS_CONFIG_FILENAME     "atx.config.sys.json"
#define ATX_LINQD_CONFIG_FILENAME   "atx.config.linqd.json"

#define ATX_DIS_CONFIG_PATH         "/etc/"ATX_DIS_CONFIG_FILENAME
#define ATX_SYS_CONFIG_PATH         "/etc/"ATX_SYS_CONFIG_FILENAME
#define ATX_LINQD_CONFIG_PATH       "/etc/"ATX_LINQD_CONFIG_FILENAME

#define ATX_DIS_LOG_PATH            "/var/log/atx-dis.log"


/* atx-dis config struct */
typedef struct {
  int dis;
  int interval;
  int enable;
  char *product;
  char *id;
  char *ip;
  int http;
  int https;
} DisConfig;

int file_exists(const char *path);
char *readfile(char *path);
int create_cfg_file(void);
int read_cfg_file(DisConfig *cfg);
void cfg_init(DisConfig *cfg);
int read_sys_file(DisConfig *cfg);
int read_linqd_file(DisConfig *cfg);

#endif