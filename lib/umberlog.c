/* umberlog.c -- CEE-enhanced syslog API.
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
#include <limits.h>
#include <time.h>

#include "umberlog.h"

#if __USE_FORTIFY_LEVEL > 0
static void (*old_syslog_chk) ();
#else
static void (*old_syslog) ();
#endif

static void (*old_openlog) ();
static int (*old_setlogmask) ();

static void ul_init (void) __attribute__((constructor));

static __thread struct
{
  int mask;
  int flags;

  int facility;
  pid_t pid;
  uid_t uid;
  gid_t gid;
  const char *ident;
  char hostname[HOST_NAME_MAX + 1];
} ul_sys_settings;

static void
ul_init (void)
{
#if __USE_FORTIFY_LEVEL > 0
  old_syslog_chk = dlsym (RTLD_NEXT, "__syslog_chk");
#else
  old_syslog = dlsym (RTLD_NEXT, "syslog");
#endif
  old_openlog = dlsym (RTLD_NEXT, "openlog");
  old_setlogmask = dlsym (RTLD_NEXT, "setlogmask");
}

void
ul_openlog (const char *ident, int option, int facility)
{
  old_openlog (ident, option, facility);
  ul_sys_settings.mask = old_setlogmask (0);
  ul_sys_settings.flags = option;
  ul_sys_settings.facility = facility;
  ul_sys_settings.pid = getpid ();
  ul_sys_settings.gid = getgid ();
  ul_sys_settings.uid = getuid ();
  ul_sys_settings.ident = ident;

  gethostname (ul_sys_settings.hostname, HOST_NAME_MAX);
}

/** HELPERS **/
static inline const char *
_find_facility (void)
{
  int i = 0;

  while (facilitynames[i].c_name != NULL &&
         facilitynames[i].c_val != ul_sys_settings.facility)
    i++;

  if (facilitynames[i].c_val == ul_sys_settings.facility)
    return facilitynames[i].c_name;
  return "<unknown>";
}

static inline const char *
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

static inline pid_t
_find_pid (void)
{
  if (ul_sys_settings.flags & LOG_UL_NOCACHE)
    return getpid ();
  else
    return ul_sys_settings.pid;
}

static inline uid_t
_get_uid (void)
{
  if (ul_sys_settings.flags & LOG_UL_NOCACHE ||
      ul_sys_settings.flags & LOG_UL_NOCACHE_UID)
    return getuid ();
  else
    return ul_sys_settings.uid;
}

static inline uid_t
_get_gid (void)
{
  if (ul_sys_settings.flags & LOG_UL_NOCACHE ||
      ul_sys_settings.flags & LOG_UL_NOCACHE_UID)
    return getgid ();
  else
    return ul_sys_settings.gid;
}

static inline const char *
_get_hostname (void)
{
  if (ul_sys_settings.flags & LOG_UL_NOCACHE)
    gethostname (ul_sys_settings.hostname, HOST_NAME_MAX);
  return ul_sys_settings.hostname;
}

static inline struct json_object *
_ul_json_vappend (struct json_object *json, va_list ap)
{
  char *key;

  while ((key = (char *)va_arg (ap, char *)) != NULL)
    {
      char *fmt = (char *)va_arg (ap, char *);
      char *value;

      if (vasprintf (&value, fmt, ap) == -1)
        abort ();
      json_object_object_add (json, key, json_object_new_string (value));
      free (value);
    }
  return json;
}

static inline struct json_object *
_ul_json_append (struct json_object *json, ...)
{
  va_list ap;

  va_start (ap, json);
  _ul_json_vappend (json, ap);
  va_end (ap);

  return json;
}

static inline void
_ul_json_append_timestamp (struct json_object *jo)
{
  struct timespec ts;
  struct tm *tm;
  char stamp[64], zone[16];

  clock_gettime (CLOCK_REALTIME, &ts);

  tm = localtime (&ts.tv_sec);

  strftime (stamp, sizeof (stamp), "%FT%T", tm);
  strftime (zone, sizeof (zone), "%z", tm);

  _ul_json_append (jo, "timestamp", "%s.%lu%s",
                   stamp, ts.tv_nsec, zone,
                   NULL);
}

static inline void
_ul_discover (struct json_object *jo, int priority)
{
  if (ul_sys_settings.flags & LOG_UL_NODISCOVER)
    return;

  _ul_json_append (jo,
                   "pid", "%d", _find_pid (),
                   "facility", "%s", _find_facility (),
                   "priority", "%s", _find_prio (priority),
                   "program", "%s", ul_sys_settings.ident,
                   "uid", "%d", _get_uid (),
                   "gid", "%d", _get_gid (),
                   "host", "%s", _get_hostname (),
                   NULL);

  if (ul_sys_settings.flags & LOG_UL_NOTIME)
    return;

  _ul_json_append_timestamp (jo);
}

static inline struct json_object *
_ul_vformat (struct json_object *jo, int format_version,
             int priority, const char *msg_format,
             va_list ap)
{
  char *value;

  if (vasprintf (&value, msg_format, ap) == -1)
    abort ();
  json_object_object_add (jo, "msg", json_object_new_string (value));
  free (value);

  if (format_version > 0)
    _ul_json_vappend (jo, ap);

  _ul_discover (jo, priority);

  return jo;
}

static inline const char *
_ul_vformat_str (struct json_object *jo, int format_version,
                 int priority, const char *msg_format,
                 va_list ap)
{
  return json_object_to_json_string (_ul_vformat (jo, format_version,
                                                  priority, msg_format,
                                                  ap));
}

/** Public API **/
char *
ul_format (int priority, const char *msg_format, ...)
{
  char *result;
  va_list ap;

  va_start (ap, msg_format);
  result = ul_vformat (priority, msg_format, ap);
  va_end (ap);

  return result;
}

char *
ul_vformat (int priority, const char *msg_format, va_list ap)
{
  struct json_object *jo = json_object_new_object ();
  char *result;

  result = strdup (_ul_vformat_str (jo, 1, priority, msg_format, ap));
  json_object_put (jo);
  return result;
}

void
ul_syslog (int priority, const char *msg_format, ...)
{
  va_list ap;

  va_start (ap, msg_format);
  ul_vsyslog (priority, msg_format, ap);
  va_end (ap);
}

static inline void
_ul_vsyslog (int format_version, int priority,
             const char *msg_format, va_list ap)
{
  struct json_object *jo;

  if (!(ul_sys_settings.mask & priority))
    return;

  jo = _ul_vformat (json_object_new_object (), format_version,
                    priority, msg_format, ap);
#if __USE_FORTIFY_LEVEL > 0
  old_syslog_chk (priority, __USE_FORTIFY_LEVEL - 1, "@cee:%s",
                  json_object_to_json_string (jo));
#else
  old_syslog (priority, "@cee:%s", json_object_to_json_string (jo));
#endif
  json_object_put (jo);
}

void
ul_vsyslog (int priority, const char *msg_format, va_list ap)
{
  _ul_vsyslog (1, priority, msg_format, ap);
}

void
ul_legacy_vsyslog (int priority, const char *msg_format, va_list ap)
{
  _ul_vsyslog (0, priority, msg_format, ap);
}

void
ul_legacy_syslog (int priority, const char *msg_format, ...)
{
  va_list ap;

  va_start (ap, msg_format);
  ul_legacy_vsyslog (priority, msg_format, ap);
  va_end (ap);
}

int
ul_setlogmask (int mask)
{
  if (mask != 0)
    ul_sys_settings.mask = mask;
  return old_setlogmask (mask);
}

#if __USE_FORTIFY_LEVEL > 0
void
__syslog_chk (int __pri, int __flag, __const char *__fmt, ...)
{
  va_list ap;

  va_start (ap, __fmt);
  ul_legacy_vsyslog (__pri, __fmt, ap);
  va_end (ap);
}

void
__vsyslog_chk (int __pri, int __flag, __const char *__fmt, va_list ap)
{
  ul_legacy_vsyslog (__pri, __fmt, ap);
}
#endif

void openlog (const char *ident, int option, int facility)
  __attribute__((alias ("ul_openlog")));

void syslog (int priority, const char *msg_format, ...)
  __attribute__((alias ("ul_legacy_syslog")));

void vsyslog (int priority, const char *msg_format, va_list ap)
  __attribute__((alias ("ul_legacy_vsyslog")));

int setlogmask (int mask)
  __attribute__((alias ("ul_setlogmask")));
