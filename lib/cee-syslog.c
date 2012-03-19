/* cee-syslog.c -- CEE-enhanced syslog API.
 *
 * Copyright (c) 2012 BalaBit IT Security Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY BALABIT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BALABIT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _GNU_SOURCE 1

#include "cee-syslog.h"

#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <json.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

static void (*old_syslog) ();

static void cee_init (void) __attribute__((constructor));

static void
cee_init (void)
{
  old_syslog = dlsym (RTLD_NEXT, "syslog");
}

static const char *
_cee_vformat (struct json_object **json, const char *msg_format, va_list ap)
{
  struct json_object *jo;
  char *key, *fmt;
  char *value;

  jo = json_object_new_object ();

  vasprintf (&value, msg_format, ap);
  json_object_object_add (jo, "msg", json_object_new_string (value));
  free (value);

  while ((key = (char *)va_arg (ap, char *)) != NULL)
    {
      fmt = (char *)va_arg (ap, char *);

      vasprintf (&value, fmt, ap);
      json_object_object_add (jo, key,
                              json_object_new_string (value));
      free (value);
    }

  *json = jo;
  return json_object_to_json_string (jo);
}

char *
cee_format (const char *msg_format, ...)
{
  char *result;
  va_list ap;

  va_start (ap, msg_format);
  result = cee_vformat (msg_format, ap);
  va_end (ap);

  return result;
}

char *
cee_vformat (const char *msg_format, va_list ap)
{
  struct json_object *jo;
  char *result;

  result = strdup (_cee_vformat (&jo, msg_format, ap));
  json_object_put (jo);
  return result;
}

void
cee_syslog (int priority, const char *msg_format, ...)
{
  va_list ap;

  va_start (ap, msg_format);
  vsyslog (priority, msg_format, ap);
  va_end (ap);
}

void
cee_vsyslog (int priority, const char *msg_format, va_list ap)
{
  struct json_object *jo;

  old_syslog (priority, "@cee:%s", _cee_vformat (&jo, msg_format, ap));
  json_object_put (jo);
}
