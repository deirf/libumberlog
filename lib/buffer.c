/* buffer.c -- Auto-growing string buffers
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

#include "config.h"
#include "buffer.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static __thread ul_buffer_t escape_buffer;

static void ul_buffer_finish (void) __attribute__((destructor));

static void
ul_buffer_finish (void)
{
  free (escape_buffer.msg);
}

static inline int
_ul_str_escape (const char *str, char *dest, size_t *length)
{
  /* Assumes ASCII!  Keep in sync with the switch! */
  static const unsigned char json_exceptions[UCHAR_MAX + 1] =
    {
      [0x01] = 1, [0x02] = 1, [0x03] = 1, [0x04] = 1, [0x05] = 1, [0x06] = 1,
      [0x07] = 1, [0x08] = 1, [0x09] = 1, [0x0a] = 1, [0x0b] = 1, [0x0c] = 1,
      [0x0d] = 1, [0x0e] = 1, [0x0f] = 1, [0x10] = 1, [0x11] = 1, [0x12] = 1,
      [0x13] = 1, [0x14] = 1, [0x15] = 1, [0x16] = 1, [0x17] = 1, [0x18] = 1,
      [0x19] = 1, [0x1a] = 1, [0x1b] = 1, [0x1c] = 1, [0x1d] = 1, [0x1e] = 1,
      [0x1f] = 1, ['\\'] = 1, ['"'] = 1
    };

  const unsigned char *p;
  char *q;

  if (!str)
    return -1;

  p = (unsigned char *)str;
  q = dest;

  while (*p)
    {
      if (json_exceptions[*p] == 0)
        *q++ = *p;
      else
        {
          /* Keep in sync with json_exceptions! */
          switch (*p)
            {
            case '\b':
              *q++ = '\\';
              *q++ = 'b';
              break;
            case '\n':
              *q++ = '\\';
              *q++ = 'n';
              break;
            case '\r':
              *q++ = '\\';
              *q++ = 'r';
              break;
            case '\t':
              *q++ = '\\';
              *q++ = 't';
              break;
            case '\\':
              *q++ = '\\';
              *q++ = '\\';
              break;
            case '"':
              *q++ = '\\';
              *q++ = '"';
              break;
            default:
              {
                static const char json_hex_chars[16] = "0123456789abcdef";

                *q++ = '\\';
                *q++ = 'u';
                *q++ = '0';
                *q++ = '0';
                *q++ = json_hex_chars[(*p) >> 4];
                *q++ = json_hex_chars[(*p) & 0xf];
                break;
              }
            }
        }
      p++;
    }

  *q = 0;
  if (length)
    *length = q - dest;
  return 0;
}

static inline int
_ul_buffer_ensure_size (ul_buffer_t *buffer, size_t size)
{
  if (buffer->alloc < size)
    {
      size_t new_alloc;
      void *new_msg;

      new_alloc = buffer->alloc + size * 2;
      new_msg = realloc (buffer->msg, new_alloc);
      if (new_msg == NULL)
        return -1;
      buffer->alloc = new_alloc;
      buffer->msg = new_msg;
    }
  return 0;
}

int
ul_buffer_reset (ul_buffer_t *buffer)
{
  if (_ul_buffer_ensure_size (buffer, 512) != 0)
    return -1;
  buffer->len = 1;
  buffer->msg[0] = '{';
  return 0;
}

ul_buffer_t *
ul_buffer_append (ul_buffer_t *buffer, const char *key, const char *value)
{
  size_t lk, lv;
  size_t orig_len = buffer->len;

  /* Append the key to the buffer */
  escape_buffer.len = 0;
  if (_ul_buffer_ensure_size (&escape_buffer, strlen (key) * 6 + 1) != 0)
    goto err;
  if (_ul_str_escape (key, escape_buffer.msg, &lk) != 0)
    goto err;

  if (_ul_buffer_ensure_size (buffer, buffer->len + lk + 4) != 0)
    goto err;

  memcpy (buffer->msg + buffer->len, "\"", 1);
  memcpy (buffer->msg + buffer->len + 1, escape_buffer.msg, lk);
  memcpy (buffer->msg + buffer->len + 1 + lk, "\":\"", 3);

  /* Append the value to the buffer */
  escape_buffer.len = 0;
  if (_ul_buffer_ensure_size (&escape_buffer, strlen (value) * 6 + 1) != 0)
    goto err;
  if (_ul_str_escape (value, escape_buffer.msg, &lv) != 0)
    goto err;

  if (_ul_buffer_ensure_size (buffer, buffer->len + lk + lv + 6) != 0)
    goto err;

  memcpy (buffer->msg + buffer->len + 1 + lk + 3, escape_buffer.msg, lv);
  memcpy (buffer->msg + buffer->len + 1 + lk + 3 + lv, "\",", 2);
  buffer->len += lk + lv + 6;

  return buffer;

 err:
  buffer->len = orig_len;
  return NULL;
}

char *
ul_buffer_finalize (ul_buffer_t *buffer)
{
  if (buffer->msg[buffer->len - 1] == ',')
    {
      if (_ul_buffer_ensure_size (buffer, buffer->len + 1) != 0)
        return NULL;
      buffer->msg[buffer->len - 1] = '}';
    }
  else
    {
      if (_ul_buffer_ensure_size (buffer, buffer->len + 2) != 0)
        return NULL;
      buffer->msg[buffer->len++] = '}';
    }
  buffer->msg[buffer->len] = '\0';
  return buffer->msg;
}
