#ifndef JSON_WRAPPER_H
#define JSON_WRAPPER_H

#include "tiny-json.h"

/* JSON Integer Response Struct */
typedef struct {
  int ok;
  int value;
} JsonIntResponse;

/* JSON String Response Struct */
typedef struct {
  int ok;
  char *value;
} JsonStringResponse;

JsonIntResponse readIntField(json_t const *parent, char const *fieldname);
//char const *readStringField(json_t const *parent, char const *fieldname);
JsonStringResponse readStringField(json_t const *parent, char const *fieldname);

#endif