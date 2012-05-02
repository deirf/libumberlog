/* umberlog.h -- CEE-enhanced syslog API.
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

#ifndef UMBERLOG_H
#define UMBERLOG_H 1

#include <syslog.h>
#include <stdarg.h>

#define LOG_UL_NODISCOVER      0x0040
#define LOG_UL_NOCACHE         0x0080
#define LOG_UL_NOCACHE_UID     0x0100
#define LOG_UL_NOTIME          0x0200

char *ul_format (int priority, const char *msg_format, ...)
  __attribute__((sentinel));
char *ul_vformat (int priority, const char *msg_format, va_list ap);

void ul_openlog (const char *ident, int option, int facility);
void ul_closelog (void);
int ul_setlogmask (int mask);

int ul_syslog (int priority, const char *msg_format, ...)
  __attribute__((warn_unused_result, sentinel));
int ul_vsyslog (int priority, const char *msg_format, va_list ap)
  __attribute__((warn_unused_result));

void ul_legacy_syslog (int priority, const char *msg_format, ...);
void ul_legacy_vsyslog (int priority, const char *msg_format, va_list ap);

#endif
