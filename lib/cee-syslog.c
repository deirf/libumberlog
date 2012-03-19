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
#define SYSLOG_NAMES 1

#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <json.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "cee-syslog.h"

static void (*old_syslog) ();
static void (*old_openlog) ();

static void cee_init (void) __attribute__((constructor));

static __thread struct
{
  int flags;
  int facility;
  pid_t pid;
} cee_sys_settings;

static void
cee_init (void)
{
  old_syslog = dlsym (RTLD_NEXT, "syslog");
  old_openlog = dlsym (RTLD_NEXT, "openlog");
}

void
cee_openlog (const char *ident, int option, int facility)
{
  old_openlog (ident, option, facility);
  cee_sys_settings.flags = option;
  cee_sys_settings.facility = facility;
  cee_sys_settings.pid = getpid ();
}

/** HELPERS **/
static const char *
_find_facility (void)
{
  int i = 0;

  while (facilitynames[i].c_name != NULL &&
         facilitynames[i].c_val != cee_sys_settings.facility)
    i++;

  if (facilitynames[i].c_val == cee_sys_settings.facility)
    return facilitynames[i].c_name;
  return "<unknown>";
}

static const char *
_find_prio (int prio)
{
  int i = 0;

  while (prioritynames[i].c_name != NULL &&
         prioritynames[i].c_val != prio)
    i++;

  if (prioritynames[i].c_val == prio)
    return prioritynames[i].c_name;
  return "<unknown>";
}

static inline const pid_t
_find_pid (void)
{
  if (cee_sys_settings.flags & LOG_CEE_NOCACHE)
    return getpid ();
  else
    return cee_sys_settings.pid;
}

static struct json_object *
_cee_json_vappend (struct json_object *json, va_list ap)
{
  char *key;

  while ((key = (char *)va_arg (ap, char *)) != NULL)
    {
      char *fmt = (char *)va_arg (ap, char *);
      char *value;

      vasprintf (&value, fmt, ap);
      json_object_object_add (json, key, json_object_new_string (value));
      free (value);
    }
  return json;
}

static struct json_object *
_cee_json_append (struct json_object *json, ...)
{
  va_list ap;

  va_start (ap, json);
  _cee_json_vappend (json, ap);
  va_end (ap);

  return json;
}

static inline void
_cee_discover (struct json_object *jo, int priority)
{
  if (cee_sys_settings.flags & LOG_CEE_NODISCOVER)
    return;

  _cee_json_append (jo,
                    "pid", "%d", _find_pid (),
                    "facility", "%s", _find_facility (),
                    "priority", "%s", _find_prio (priority),
                    NULL);
}

static struct json_object *
_cee_vformat (struct json_object *jo, int format_version,
              int priority, const char *msg_format,
              va_list ap)
{
  char *value;

  vasprintf (&value, msg_format, ap);
  json_object_object_add (jo, "msg", json_object_new_string (value));
  free (value);

  if (format_version > 0)
    _cee_json_vappend (jo, ap);

  _cee_discover (jo, priority);

  return jo;
}

static inline const char *
_cee_vformat_str (struct json_object *jo, int format_version,
                  int priority, const char *msg_format,
                  va_list ap)
{
  return json_object_to_json_string (_cee_vformat (jo, format_version,
                                                   priority, msg_format,
                                                   ap));
}

/** Public API **/
char *
cee_format (int priority, const char *msg_format, ...)
{
  char *result;
  va_list ap;

  va_start (ap, msg_format);
  result = cee_vformat (priority, msg_format, ap);
  va_end (ap);

  return result;
}

char *
cee_vformat (int priority, const char *msg_format, va_list ap)
{
  struct json_object *jo = json_object_new_object ();
  char *result;

  result = strdup (_cee_vformat_str (jo, 1, priority, msg_format, ap));
  json_object_put (jo);
  return result;
}

void
cee_syslog (int priority, const char *msg_format, ...)
{
  va_list ap;

  va_start (ap, msg_format);
  cee_vsyslog (priority, msg_format, ap);
  va_end (ap);
}

static inline void
_cee_vsyslog (int format_version, int priority,
              const char *msg_format, va_list ap)
{
  struct json_object *jo = json_object_new_object ();

  _cee_vformat (jo, format_version, priority, msg_format, ap);
  old_syslog (priority, "@cee:%s", json_object_to_json_string (jo));
  json_object_put (jo);
}

void
cee_vsyslog (int priority, const char *msg_format, va_list ap)
{
  _cee_vsyslog (1, priority, msg_format, ap);
}

void
_cee_old_vsyslog (int priority, const char *msg_format, va_list ap)
{
  _cee_vsyslog (0, priority, msg_format, ap);
}

void
_cee_old_syslog (int priority, const char *msg_format, ...)
{
  va_list ap;

  va_start (ap, msg_format);
  _cee_old_vsyslog (priority, msg_format, ap);
  va_end (ap);
}

void openlog (const char *ident, int option, int facility)
  __attribute__((alias ("cee_openlog")));

void syslog (int priority, const char *msg_format, ...)
  __attribute__((alias ("_cee_old_syslog")));

void vsyslog (int priority, const char *msg_format, va_list ap)
  __attribute__((alias ("_cee_old_vsyslog")));
