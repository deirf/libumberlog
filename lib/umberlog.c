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
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <wchar.h>

#include "config.h"
#include "umberlog.h"
#include "buffer.h"

static void (*old_syslog) ();
static void (*old_vsyslog) ();
static void (*old_openlog) ();
static void (*old_closelog) ();
static int (*old_setlogmask) ();

static void ul_init (void) __attribute__((constructor));
static void ul_finish (void) __attribute__((destructor));

static __thread struct
{
  int mask;
  int flags;

  int facility;
  pid_t pid;
  uid_t uid;
  gid_t gid;
  const char *ident;
  char hostname[_POSIX_HOST_NAME_MAX + 1];
} ul_sys_settings;

static __thread ul_buffer_t ul_buffer;
static __thread int ul_recurse;

static void
ul_init (void)
{
  old_syslog = dlsym (RTLD_NEXT, "syslog");
  old_vsyslog = dlsym (RTLD_NEXT, "vsyslog");
  old_openlog = dlsym (RTLD_NEXT, "openlog");
  old_closelog = dlsym (RTLD_NEXT, "closelog");
  old_setlogmask = dlsym (RTLD_NEXT, "setlogmask");
}

static void
ul_finish (void)
{
  free (ul_buffer.msg);
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

  gethostname (ul_sys_settings.hostname, _POSIX_HOST_NAME_MAX);
}

void
ul_closelog (void)
{
  old_closelog ();
  memset (&ul_sys_settings, 0, sizeof (ul_sys_settings));
}

/** HELPERS **/
static inline const char *
_find_facility (int prio)
{
  int i = 0;
  int fac = prio & LOG_FACMASK;

  if (fac == 0)
    fac = ul_sys_settings.facility;

  while (facilitynames[i].c_name != NULL &&
         facilitynames[i].c_val != fac)
    i++;

  if (facilitynames[i].c_val == fac)
    return facilitynames[i].c_name;
  return "<unknown>";
}

static inline const char *
_find_prio (int prio)
{
  int i = 0;
  int pri = LOG_PRI (prio);

  while (prioritynames[i].c_name != NULL &&
         prioritynames[i].c_val != pri)
    i++;

  if (prioritynames[i].c_val == pri)
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
    gethostname (ul_sys_settings.hostname, _POSIX_HOST_NAME_MAX);
  return ul_sys_settings.hostname;
}

#define _ul_va_spin(fmt,ap)                             \
  {                                                     \
    size_t i;                                           \
                                                        \
    for (i = 0; i < strlen (fmt); i++)                  \
      {                                                 \
        int eof = 0;                                    \
                                                        \
        if (fmt[i] != '%')                              \
          continue;                                     \
        i++;                                            \
        while (eof != 1)                                \
          {                                             \
            switch (fmt[i])                             \
              {                                         \
              case 'd':                                 \
              case 'i':                                 \
              case 'o':                                 \
              case 'u':                                 \
              case 'x':                                 \
              case 'X':                                 \
                if (fmt[i - 1] == 'l')                  \
                  {                                     \
                    if (i - 2 > 0 && fmt[i - 2] == 'l') \
                      (void)va_arg (ap, long long int); \
                    else                                \
                      (void)va_arg (ap, long int);      \
                  }                                     \
                else                                    \
                  (void)va_arg (ap, int);               \
                eof = 1;                                \
                break;                                  \
              case 'e':                                 \
              case 'E':                                 \
              case 'f':                                 \
              case 'F':                                 \
              case 'g':                                 \
              case 'G':                                 \
              case 'a':                                 \
              case 'A':                                 \
                if (fmt[i - 1] == 'L')                  \
                  (void)va_arg (ap, long double);       \
                else                                    \
                  (void)va_arg (ap, double);            \
                eof = 1;                                \
                break;                                  \
              case 'c':                                 \
                if (fmt [i - 1] == 'l')                 \
                  (void)va_arg (ap, wint_t);            \
                else                                    \
                  (void)va_arg (ap, int);               \
                eof = 1;                                \
                break;                                  \
              case 's':                                 \
                if (fmt [i - 1] == 'l')                 \
                  (void)va_arg (ap, wchar_t *);         \
                else                                    \
                  (void)va_arg (ap, char *);            \
                eof = 1;                                \
                break;                                  \
              case 'p':                                 \
                (void)va_arg (ap, void *);              \
                eof = 1;                                \
                break;                                  \
              case '%':                                 \
                eof = 1;                                \
                break;                                  \
              default:                                  \
                i++;                                    \
              }                                         \
          }                                             \
      }                                                 \
  }

static inline ul_buffer_t *
_ul_json_vappend (ul_buffer_t *buffer, va_list ap_orig)
{
  va_list ap;
  char *key;

  /* "&ap" may not be possible for function parameters, so make a copy. */
  va_copy (ap, ap_orig);
  while ((key = (char *)va_arg (ap, char *)) != NULL)
    {
      char *fmt = (char *)va_arg (ap, char *);
      char *value = NULL;
      va_list aq;

      va_copy (aq, ap);
      if (vasprintf (&value, fmt, aq) == -1)
        {
          va_end (aq);
	  goto err;
        }
      va_end (aq);

      if (!value)
        goto err;

      buffer = ul_buffer_append (buffer, key, value);
      free (value);

      if (buffer == NULL)
	goto err;

      _ul_va_spin (fmt, ap);
    }
  va_end (ap);

  return buffer;

 err:
  va_end (ap);
  return NULL;
}

static inline ul_buffer_t *
_ul_json_append (ul_buffer_t *buffer, ...)
{
  va_list ap;

  va_start (ap, buffer);
  buffer = _ul_json_vappend (buffer, ap);
  va_end (ap);

  return buffer;
}

static inline ul_buffer_t *
_ul_json_append_timestamp (ul_buffer_t *buffer)
{
  struct timespec ts;
  struct tm *tm;
  char stamp[64], zone[16];

  clock_gettime (CLOCK_REALTIME, &ts);

  tm = localtime (&ts.tv_sec);

  strftime (stamp, sizeof (stamp), "%FT%T", tm);
  strftime (zone, sizeof (zone), "%z", tm);

  return _ul_json_append (buffer, "timestamp", "%s.%09lu%s",
                          stamp, ts.tv_nsec, zone,
                          NULL);
}

static inline ul_buffer_t *
_ul_discover (ul_buffer_t *buffer, int priority)
{
  if (ul_sys_settings.flags & LOG_UL_NODISCOVER)
    return buffer;

  buffer = _ul_json_append (buffer,
                            "pid", "%d", _find_pid (),
                            "facility", "%s", _find_facility (priority),
                            "priority", "%s", _find_prio (priority),
                            "program", "%s", ul_sys_settings.ident,
                            "uid", "%d", _get_uid (),
                            "gid", "%d", _get_gid (),
                            "host", "%s", _get_hostname (),
                            NULL);

  if (ul_sys_settings.flags & LOG_UL_NOTIME || !buffer)
    return buffer;

  return _ul_json_append_timestamp (buffer);
}

static inline ul_buffer_t *
_ul_vformat (ul_buffer_t *buffer, int format_version,
             int priority, const char *msg_format,
             va_list ap_orig)
{
  char *value;
  va_list ap, aq;

  /* "&ap" may not be possible for function parameters, so make a copy. */
  va_copy (ap, ap_orig);
  va_copy (aq, ap);
  if (vasprintf (&value, msg_format, aq) == -1)
    {
      va_end (aq);
      goto err;
    }
  va_end (aq);
  if (!value)
    goto err;

  if (ul_buffer_reset (buffer) != 0)
    goto err;

  buffer = ul_buffer_append (buffer, "msg", value);
  free (value);

  if (buffer == NULL)
    goto err;

  _ul_va_spin (msg_format, ap);

  if (format_version > 0)
    buffer = _ul_json_vappend (buffer, ap);

  if (!buffer)
    goto err;

  va_end (ap);
  return _ul_discover (buffer, priority);

 err:
  va_end (ap);
  return NULL;
}

static inline const char *
_ul_vformat_str (ul_buffer_t *buffer, int format_version,
                 int priority, const char *msg_format,
                 va_list ap)
{
  buffer = _ul_vformat (buffer, format_version,
                        priority, msg_format, ap);
  if (!buffer)
    return NULL;

  return ul_buffer_finalize (buffer);
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
  char *result;
  const char *msg;
  ul_buffer_t *buffer = &ul_buffer;

  msg = _ul_vformat_str (buffer, 1, priority, msg_format, ap);
  if (!msg)
    {
      errno = ENOMEM;
      return NULL;
    }

  result = strdup (msg);
  return result;
}

static inline int
_ul_vsyslog (int format_version, int priority,
             const char *msg_format, va_list ap)
{
  const char *msg;
  ul_buffer_t *buffer = &ul_buffer;

  if (!(ul_sys_settings.mask & LOG_MASK (LOG_PRI (priority))))
    return 0;

  buffer = _ul_vformat (buffer, format_version, priority, msg_format, ap);
  if (buffer == NULL)
    return -1;

  old_syslog (priority, "@cee:%s", ul_buffer_finalize (buffer));

  return 0;
}

int
ul_syslog (int priority, const char *msg_format, ...)
{
  va_list ap;
  int status;

  va_start (ap, msg_format);
  status = ul_vsyslog (priority, msg_format, ap);
  va_end (ap);

  return status;
}

int
ul_vsyslog (int priority, const char *msg_format, va_list ap)
{
  return _ul_vsyslog (1, priority, msg_format, ap);
}

void
ul_legacy_vsyslog (int priority, const char *msg_format, va_list ap)
{
  if (ul_recurse)
    {
      old_vsyslog (priority, msg_format, ap);
    }
  else
    {
      ul_recurse = 1;
      _ul_vsyslog (0, priority, msg_format, ap);
    }
  ul_recurse = 0;
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

#if HAVE___SYSLOG_CHK
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

void closelog (void)
  __attribute__((alias ("ul_closelog")));

#undef syslog
void syslog (int priority, const char *msg_format, ...)
  __attribute__((alias ("ul_legacy_syslog")));

#undef vsyslog
void vsyslog (int priority, const char *msg_format, va_list ap)
  __attribute__((alias ("ul_legacy_vsyslog")));

int setlogmask (int mask)
  __attribute__((alias ("ul_setlogmask")));
