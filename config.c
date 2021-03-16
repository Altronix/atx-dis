#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"
#include "json-wrapper.h"
#include "beacon.h"
#include "config.h"

/*
  Return 1 if the file exist
*/
int file_exists(const char *path)
{
  FILE *f;
  if (f = fopen(path, "r")){
    fclose(f);
    return 1;
  }
  return 0;
}

/*
  Read file
  Return pointer to char
*/
char *readfile(char *path)
{
  char *buff = 0;
  long len;
  FILE *f = fopen(path, "r");
  if(f)
  {
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    buff = malloc(len);
    if(buff)
    {
      fread(buff, 1, len, f);
    }
    fclose(f);
  }
  return buff;
}

/*
  Create "/etc/atx.config.dis.json" file
  Return 1 if the file created successfully
*/
int create_cfg_file(void)
{
  FILE *f;
  f = fopen (ATX_DIS_CONFIG_PATH, "w");
  if(f != NULL)
  {
    fprintf(f, "{\"dis\":%d,\"interval\":%d,\"enable\":%d}", UDP_DEFAULT_BCAST_PORT, UDP_DEFAULT_BCAST_ADVERTISING_INTERVAL_SEC, UDP_DEFAULT_BCAST_ENABLED);
    fclose(f);
    return 1; 
  }
  return 0;
}

/*
  Read /etc/atx.config.dis.json
  Update "dis", "interval" and "enable" fields of *cfg object
*/
int read_cfg_file(DisConfig *cfg)
{
  enum { MAX_FIELDS = 12 };
  json_t pool[ MAX_FIELDS ];

  char *str=readfile(ATX_DIS_CONFIG_PATH);
  log_info("cfg file: %s \n", str);

  json_t const* parent = json_create( str, pool, MAX_FIELDS );
  if( parent == NULL ) return EXIT_FAILURE;

  if (readIntField(parent, "dis").ok)
  {
    // Reading "dis" field
    cfg->dis = readIntField(parent, "dis").value;
    log_debug("dis: %d", cfg->dis);
  }

  if (readIntField(parent, "interval").ok)
  {
    // Reading "interval" field
    cfg->interval = readIntField(parent, "interval").value;
    log_debug("interval: %d", cfg->interval );
  }

  if (readIntField(parent, "enable").ok)
  {
    // Reading "enable" field
    cfg->enable = readIntField(parent, "enable").value;
    log_debug("enable: %d", cfg->enable );  
  }

  free(str);
}

/*
  Read and or Create json "atx.config.dis.json" file
  and update "cfg" object 
*/
void cfg_init(DisConfig *cfg)
{
  if(!file_exists(ATX_DIS_CONFIG_PATH)) { 
    log_warn("%s does not exists.", ATX_DIS_CONFIG_PATH);
    log_info("Creating %s", ATX_DIS_CONFIG_FILENAME);
    create_cfg_file();
    read_cfg_file(cfg); 
    read_sys_file(cfg);
    read_linqd_file(cfg);
  }
  else 
  {
    log_info("%s found.", ATX_DIS_CONFIG_PATH);
    read_cfg_file(cfg);
    read_sys_file(cfg); 
    read_linqd_file(cfg); 
  }
}

/*
  Read "atx.config.sys.json" file
  and update "cfg" object 
*/
int read_sys_file(DisConfig *cfg)
{
  enum { MAX_FIELDS = 16 };
  json_t pool[ MAX_FIELDS ];

  char *str=readfile(ATX_SYS_CONFIG_PATH);
  log_info("sys file: %s \n", str);

  json_t const* parent = json_create( str, pool, MAX_FIELDS );
  if( parent == NULL ) return EXIT_FAILURE;

  json_t const* namefield = json_getProperty( parent, "ipv4" );
  if ( namefield == NULL ) return EXIT_FAILURE;
  if ( json_getType( namefield ) != JSON_OBJ ) return EXIT_FAILURE;

  if (readStringField(namefield, "ip").ok)
  {
    cfg->ip = readStringField(namefield, "ip").value;
    log_debug("ip: %s \n", cfg->ip);
  }

  if (readStringField(namefield, "hn").ok)
  {
    cfg->id = readStringField(namefield, "hn").value;
    log_debug("hn: %s \n", cfg->id);
  }

  free(str);
}

/*
  Read "atx.config.linqd.json" file
  and update "cfg" object 
*/
int read_linqd_file(DisConfig *cfg)
{
  enum { MAX_FIELDS = 32 };
  json_t pool[ MAX_FIELDS ];

  char *str=readfile(ATX_LINQD_CONFIG_PATH);
  log_info("linqd file: %s \n", str);

  json_t const* parent = json_create( str, pool, MAX_FIELDS );
  if( parent == NULL ) return EXIT_FAILURE;

  json_t const* namefield = json_getProperty( parent, "ports" );
  if ( namefield == NULL ) return EXIT_FAILURE;
  if ( json_getType( namefield ) != JSON_OBJ ) return EXIT_FAILURE;

  if (readIntField(namefield, "http").ok)
  {
    cfg->http = readIntField(namefield, "http").value;
    log_debug("http: %d \n", cfg->http);
  }

  if (readIntField(namefield, "https").ok)
  {
    cfg->https = readIntField(namefield, "https").value;
    log_debug("https: %d \n", cfg->https);
  }

  free(str);
}

  



