#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"
#include "tiny-json.h"
#include "json-wrapper.h"

/*
  Read Integer json field value
*/
JsonIntResponse readIntField(json_t const *parent, char const *fieldname)
{
  JsonIntResponse res;
  res.ok = true;
  json_t const *field = json_getProperty( parent, fieldname );

  if (field == NULL)
  {
    res.ok = false;
  } 
  if (json_getType(field) != JSON_INTEGER) 
  {
    res.ok = false; 
  }
  if (res.ok)
  {
    res.value = (int)json_getInteger( field );
  }
  
  return res;
}

/*
  Read String (*char) json field value
*/
JsonStringResponse readStringField(json_t const *parent, char const *fieldname)
{
  JsonStringResponse res;
  res.ok = true;
  json_t const *field = json_getProperty( parent, fieldname );

  if (field == NULL)
  {
    res.ok = false;
  } 
  if (json_getType(field) != JSON_TEXT) 
  {
    res.ok = false; 
  }
  if (res.ok)
  {
    res.value = (char*)json_getValue( field );
  }

  return res;
}
