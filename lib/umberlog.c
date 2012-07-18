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

#include "config.h"
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <wchar.h>
#ifdef HAVE_PARSE_PRINTF_FORMAT
#include <printf.h>
#endif

#include "umberlog.h"
#include "buffer.h"

static void (*old_syslog) ();
static void (*old_vsyslog) ();
static void (*old_openlog) ();
static void (*old_closelog) ();

static void ul_init (void) __attribute__((constructor));
static void ul_finish (void) __attribute__((destructor));

static struct
{
  /* The lock is used only to serialize writes; we assume that reads are safe
     even when racing with writes, note that POSIX does not guarantee this (but
     the BSD syslog does the same thing). */
  pthread_mutex_t lock;
  int flags;
  int facility;
  const char *ident;

  /* Cached data */
  pid_t pid;			/* -1 = no value cached */
  uid_t uid;			/* (uid_t)-1 = no value cached */
  gid_t gid;			/* (gid_t)-1 = no value cached */
  char hostname[_POSIX_HOST_NAME_MAX + 1]; /* "" = no value cached */
} ul_process_data =
  {
    PTHREAD_MUTEX_INITIALIZER, 0, LOG_USER, NULL,
    -1, (uid_t)-1, (gid_t)-1, { 0, }
  };

static __thread ul_buffer_t ul_buffer;
static __thread int ul_recurse;

static void
ul_init (void)
{
  old_syslog = dlsym (RTLD_NEXT, "syslog");
  old_vsyslog = dlsym (RTLD_NEXT, "vsyslog");
  old_openlog = dlsym (RTLD_NEXT, "openlog");
  old_closelog = dlsym (RTLD_NEXT, "closelog");
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
  pthread_mutex_lock (&ul_process_data.lock);
  ul_process_data.flags = option;
  ul_process_data.facility = facility;
  ul_process_data.ident = ident;

  if ((ul_process_data.flags & (LOG_UL_NODISCOVER | LOG_UL_NOCACHE)) != 0)
    ul_process_data.pid = -1;
  else
    ul_process_data.pid = getpid ();
  if ((ul_process_data.flags &
       (LOG_UL_NODISCOVER | LOG_UL_NOCACHE | LOG_UL_NOCACHE_UID)) != 0)
    {
      ul_process_data.gid = (gid_t)-1;
      ul_process_data.uid = (uid_t)-1;
    }
  else
    {
      ul_process_data.gid = getgid ();
      ul_process_data.uid = getuid ();
    }
  if ((ul_process_data.flags & (LOG_UL_NODISCOVER | LOG_UL_NOCACHE)) != 0)
    ul_process_data.hostname[0] = '\0';
  else
    gethostname (ul_process_data.hostname, _POSIX_HOST_NAME_MAX);
  pthread_mutex_unlock (&ul_process_data.lock);
}

void
ul_closelog (void)
{
  old_closelog ();
  pthread_mutex_lock (&ul_process_data.lock);
  ul_process_data.ident = NULL;

  ul_process_data.pid = -1;
  ul_process_data.gid = (gid_t)-1;
  ul_process_data.uid = (uid_t)-1;
  ul_process_data.hostname[0] = '\0';
  pthread_mutex_unlock (&ul_process_data.lock);
}

/** HELPERS **/
static inline const char *
_find_facility (int prio)
{
  int i = 0;
  int fac = prio & LOG_FACMASK;

  if (fac == 0)
    fac = ul_process_data.facility;

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
  pid_t pid;

  pid = ul_process_data.pid;
  if (pid == -1)
    pid = getpid ();
  return pid;
}

static inline uid_t
_get_uid (void)
{
  uid_t uid;

  uid = ul_process_data.uid;
  if (uid == (uid_t)-1)
    uid = getuid ();
  return uid;
}

static inline gid_t
_get_gid (void)
{
  gid_t gid;

  gid = ul_process_data.gid;
  if (gid == (gid_t)-1)
    gid = getgid ();
  return gid;
}

static inline const char *
_get_hostname (char *hostname_buffer)
{
  if (ul_process_data.hostname[0] != '\0')
    return ul_process_data.hostname;

  gethostname (hostname_buffer, _POSIX_HOST_NAME_MAX);
  return hostname_buffer;
}

static inline const char *
_get_ident (void)
{
  const char *ident;

  ident = ul_process_data.ident;
#ifdef HAVE_PROGRAM_INVOCATION_SHORT_NAME
  if (ident == NULL)
    ident = program_invocation_short_name;
#endif
  return ident;
}

#ifdef HAVE_PARSE_PRINTF_FORMAT

#define _ul_va_spin _ul_va_spin_glibc

static int
_ul_va_spin_glibc (const char *fmt, va_list *pap)
{
  size_t num_args, i;
  int *types;

  num_args = parse_printf_format (fmt, 0, NULL);
  types = malloc (num_args * sizeof (*types));
  if (types == NULL)
    goto err;
  if (parse_printf_format (fmt, num_args, types) != num_args)
    goto err; /* Should never happen */

  for (i = 0; i < num_args; i++)
    {
      switch (types[i])
        {
        case PA_CHAR:
        case PA_INT | PA_FLAG_SHORT:
        case PA_INT:
          (void)va_arg (*pap, int);
          break;
        case PA_INT | PA_FLAG_LONG:
          (void)va_arg (*pap, long int);
          break;
        case PA_INT | PA_FLAG_LONG_LONG:
          (void)va_arg (*pap, long long int);
          break;

        case PA_WCHAR:
          (void)va_arg (*pap, wint_t);
          break;

        case PA_STRING:
          (void)va_arg (*pap, char *);
          break;

        case PA_WSTRING:
          (void)va_arg (*pap, wchar_t *);
          break;

        case PA_POINTER:
          (void)va_arg (*pap, void *);
          break;

        case PA_FLOAT:
        case PA_DOUBLE:
          (void)va_arg (*pap, double);
          break;
        case PA_DOUBLE | PA_FLAG_LONG_DOUBLE:
          (void)va_arg (*pap, long double);
          break;

        default:
          if ((types[i] & PA_FLAG_PTR) != 0)
            {
              (void)va_arg (*pap, void *);
              break;
            }
          /* Unknown user-defined parameter type.  Can we log that this
             happened? */
          goto err;
        }
    }

  free (types);
  return 0;

 err:
  free (types);
  return -1;
}
#else /* !HAVE_PARSE_PRINTF_FORMAT */

#define _ul_va_spin _ul_va_spin_legacy

static int
_ul_va_spin_legacy (const char *fmt, va_list *pap)
{
  size_t i;

  for (i = 0; i < strlen (fmt); i++)
    {
      int eof = 0;

      if (fmt[i] != '%')
        continue;
      i++;
      while (eof != 1)
        {
          switch (fmt[i])
            {
            case 'd':
            case 'i':
            case 'o':
            case 'u':
            case 'x':
            case 'X':
              if (fmt[i - 1] == 'l')
                {
                  if (i - 2 > 0 && fmt[i - 2] == 'l')
                    (void)va_arg (*pap, long long int);
                  else
                    (void)va_arg (*pap, long int);
                }
              else if (fmt[i - 1] == 'j')
                (void)va_arg (*pap, intmax_t);
              else if (fmt[i - 1] == 'z')
                (void)va_arg (*pap, ssize_t);
              else if (fmt[i - 1] == 't')
                (void)va_arg (*pap, ptrdiff_t);
              else /* Also handles h, hh */
                (void)va_arg (*pap, int);
              eof = 1;
              break;
            case 'e':
            case 'E':
            case 'f':
            case 'F':
            case 'g':
            case 'G':
            case 'a':
            case 'A':
              if (fmt[i - 1] == 'L')
                (void)va_arg (*pap, long double);
              else
                (void)va_arg (*pap, double);
              eof = 1;
              break;
            case 'c':
              if (fmt [i - 1] == 'l')
                (void)va_arg (*pap, wint_t);
              else
                (void)va_arg (*pap, int);
              eof = 1;
              break;
            case 'C':
              (void)va_arg (*pap, wint_t);
              eof = 1;
              break;
            case 's':
              if (fmt [i - 1] == 'l')
                (void)va_arg (*pap, wchar_t *);
              else
                (void)va_arg (*pap, char *);
              eof = 1;
              break;
            case 'S':
              (void)va_arg (*pap, wchar_t *);
              eof = 1;
              break;
            case 'p':
              (void)va_arg (*pap, void *);
              eof = 1;
              break;
            case 'n':
              if (fmt[i - 1] == 'l')
                {
                  if (i - 2 > 0 && fmt[i - 2] == 'l')
                    (void)va_arg (*pap, long long *);
                  else
                    (void)va_arg (*pap, long int *);
                }
              else if (fmt[i - 1] == 'h')
                {
                  if (i - 2 > 0 && fmt[i - 2] == 'h')
                    (void)va_arg (*pap, signed char *);
                  else
                    (void)va_arg (*pap, short int *);
                }
              else if (fmt[i - 1] == 'j')
                (void)va_arg (*pap, intmax_t *);
              else if (fmt[i - 1] == 'z')
                (void)va_arg (*pap, ssize_t *);
              else if (fmt[i - 1] == 't')
                (void)va_arg (*pap, ptrdiff_t *);
              else
                (void)va_arg (*pap, int *);
              eof = 1;
              break;
            case '*':
              (void)va_arg (*pap, int);
              i++;
              break; /* eof stays set to 0 */
            case '%':
              eof = 1;
              break;
            default:
              i++;
            }
        }
    }
  return 0;
}
#endif /* !HAVE_PARSE_PRINTF_FORMAT */

/* Return a newly allocated string.
   On failure, NULL is returned and it is undefined what PAP points to. */
static char *
_ul_vasprintf_and_advance (const char *fmt, va_list *pap)
{
  va_list aq;
  size_t i;
  char *res;

  va_copy (aq, *pap);
  if (vasprintf (&res, fmt, aq) < 0)
    {
      va_end (aq);
      return NULL;
    }
  va_end (aq);
  if (res == NULL)
    return NULL;

  if (_ul_va_spin (fmt, pap) != 0)
    {
      free (res);
      return NULL;
    }
  return res;
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
      char *value;

      value = _ul_vasprintf_and_advance (fmt, &ap);
      if (!value)
        goto err;
      buffer = ul_buffer_append (buffer, key, value);
      free (value);

      if (buffer == NULL)
        goto err;
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
  char hostname_buffer[_POSIX_HOST_NAME_MAX + 1];
  const char *ident;

  if (ul_process_data.flags & LOG_UL_NODISCOVER)
    return buffer;

  buffer = _ul_json_append (buffer,
                            "pid", "%d", _find_pid (),
                            "facility", "%s", _find_facility (priority),
                            "priority", "%s", _find_prio (priority),
                            "uid", "%d", _get_uid (),
                            "gid", "%d", _get_gid (),
                            "host", "%s", _get_hostname (hostname_buffer),
                            NULL);
  if (buffer == NULL)
    return buffer;

  ident = _get_ident ();
  if (ident != NULL)
    buffer = _ul_json_append (buffer, "program", "%s", ident, NULL);

  if (ul_process_data.flags & LOG_UL_NOTIME || !buffer)
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
  if (ul_buffer_reset (buffer) != 0)
    goto err;

  value = _ul_vasprintf_and_advance (msg_format, &ap);
  if (!value)
    goto err;
  buffer = ul_buffer_append (buffer, "msg", value);
  free (value);

  if (buffer == NULL)
    goto err;

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

  if (!(setlogmask (0) & LOG_MASK (LOG_PRI (priority))))
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
      ul_recurse = 0;
    }
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
  return setlogmask (mask);
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
