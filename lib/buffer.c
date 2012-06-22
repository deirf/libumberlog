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

static int
_ul_buffer_realloc_to_reserve (ul_buffer_t *buffer, size_t size)
{
  size_t new_alloc, ptr_offset;
  void *new_msg;

  new_alloc = (buffer->alloc_end - buffer->msg + size) * 2;
  ptr_offset = buffer->ptr - buffer->msg;
  new_msg = realloc (buffer->msg, new_alloc);
  if (new_msg == NULL)
    return -1;
  buffer->msg = new_msg;
  buffer->ptr = new_msg + ptr_offset;
  buffer->alloc_end = new_msg + new_alloc;
  return 0;
}

static inline int
_ul_buffer_reserve_size (ul_buffer_t *buffer, size_t size)
{
  if (buffer->alloc_end - buffer->ptr < size)
    return _ul_buffer_realloc_to_reserve (buffer, size);
  return 0;
}

static inline int
_ul_str_escape (ul_buffer_t *dest, const char *str)
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
  char *q, *end;

  if (!str)
    return -1;

  p = (unsigned char *)str;
  q = dest->ptr;
  end = dest->alloc_end;

#define BUFFER_RESERVE(SIZE)                               \
  do                                                       \
    {                                                      \
      if (end - q < (SIZE))                                \
        {                                                  \
          dest->ptr = q;                                   \
          if (_ul_buffer_reserve_size (dest, (SIZE)) != 0) \
            return -1;                                     \
          q = dest->ptr;                                   \
          end = dest->alloc_end;                           \
        }                                                  \
    }                                                      \
  while (0)

  while (*p)
    {
      if (json_exceptions[*p] == 0)
        {
          /* This is a slightly faster variant of equivalent to
             BUFFER_RESERVE (1) */
          if (q == end)
            {
              dest->ptr = q;
              if (_ul_buffer_reserve_size (dest, 1) != 0)
                return -1;
              q = dest->ptr;
              end = dest->alloc_end;
            }
          *q++ = *p;
        }
      else
        {
          /* Keep in sync with json_exceptions! */
          switch (*p)
            {
            case '\b':
              BUFFER_RESERVE (2);
              memcpy (q, "\\b", 2);
              q += 2;
              break;
            case '\n':
              BUFFER_RESERVE (2);
              memcpy (q, "\\n", 2);
              q += 2;
              break;
            case '\r':
              BUFFER_RESERVE (2);
              memcpy (q, "\\r", 2);
              q += 2;
              break;
            case '\t':
              BUFFER_RESERVE (2);
              memcpy (q, "\\t", 2);
              q += 2;
              break;
            case '\\':
              BUFFER_RESERVE (2);
              memcpy (q, "\\\\", 2);
              q += 2;
              break;
            case '"':
              BUFFER_RESERVE (2);
              memcpy (q, "\\\"", 2);
              q += 2;
              break;
            default:
              {
                static const char json_hex_chars[16] = "0123456789abcdef";

                BUFFER_RESERVE (6);
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
  dest->ptr = q;

  return 0;
}

int
ul_buffer_reset (ul_buffer_t *buffer)
{
  buffer->ptr = buffer->msg;
  if (_ul_buffer_reserve_size (buffer, 512) != 0)
    return -1;
  *buffer->ptr++ = '{';
  return 0;
}

ul_buffer_t *
ul_buffer_append (ul_buffer_t *buffer, const char *key, const char *value)
{
  size_t orig_len = buffer->ptr - buffer->msg;

  /* Append the key to the buffer */
  if (_ul_buffer_reserve_size (buffer, 1) != 0)
    goto err;
  *buffer->ptr++ = '"';

  if (_ul_str_escape (buffer, key) != 0)
    goto err;

  if (_ul_buffer_reserve_size (buffer, 3) != 0)
    goto err;
  memcpy (buffer->ptr, "\":\"", 3);
  buffer->ptr += 3;

  /* Append the value to the buffer */
  if (_ul_str_escape (buffer, value) != 0)
    goto err;

  if (_ul_buffer_reserve_size (buffer, 2) != 0)
    goto err;
  memcpy (buffer->ptr, "\",", 2);
  buffer->ptr += 2;

  return buffer;

 err:
  buffer->ptr = buffer->msg + orig_len;
  return NULL;
}

char *
ul_buffer_finalize (ul_buffer_t *buffer)
{
  if (buffer->ptr[-1] == ',')
    {
      if (_ul_buffer_reserve_size (buffer, 1) != 0)
        return NULL;
      buffer->ptr[-1] = '}';
    }
  else
    {
      if (_ul_buffer_reserve_size (buffer, 2) != 0)
        return NULL;
      *buffer->ptr++ = '}';
    }
  *buffer->ptr++ = '\0';
  return buffer->msg;
}
