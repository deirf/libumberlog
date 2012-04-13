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

#include <stdlib.h>
#include <string.h>

static const unsigned char json_exceptions[] =
  {
    0x7f,  0x80,  0x81,  0x82,  0x83,  0x84,  0x85,  0x86,
    0x87,  0x88,  0x89,  0x8a,  0x8b,  0x8c,  0x8d,  0x8e,
    0x8f,  0x90,  0x91,  0x92,  0x93,  0x94,  0x95,  0x96,
    0x97,  0x98,  0x99,  0x9a,  0x9b,  0x9c,  0x9d,  0x9e,
    0x9f,  0xa0,  0xa1,  0xa2,  0xa3,  0xa4,  0xa5,  0xa6,
    0xa7,  0xa8,  0xa9,  0xaa,  0xab,  0xac,  0xad,  0xae,
    0xaf,  0xb0,  0xb1,  0xb2,  0xb3,  0xb4,  0xb5,  0xb6,
    0xb7,  0xb8,  0xb9,  0xba,  0xbb,  0xbc,  0xbd,  0xbe,
    0xbf,  0xc0,  0xc1,  0xc2,  0xc3,  0xc4,  0xc5,  0xc6,
    0xc7,  0xc8,  0xc9,  0xca,  0xcb,  0xcc,  0xcd,  0xce,
    0xcf,  0xd0,  0xd1,  0xd2,  0xd3,  0xd4,  0xd5,  0xd6,
    0xd7,  0xd8,  0xd9,  0xda,  0xdb,  0xdc,  0xdd,  0xde,
    0xdf,  0xe0,  0xe1,  0xe2,  0xe3,  0xe4,  0xe5,  0xe6,
    0xe7,  0xe8,  0xe9,  0xea,  0xeb,  0xec,  0xed,  0xee,
    0xef,  0xf0,  0xf1,  0xf2,  0xf3,  0xf4,  0xf5,  0xf6,
    0xf7,  0xf8,  0xf9,  0xfa,  0xfb,  0xfc,  0xfd,  0xfe,
    0xff,  '\0'
  };

static inline char *
_ul_str_escape (const char *str)
{
  const unsigned char *p;
  char *dest;
  char *q;
  static unsigned char exmap[256];
  static int exmap_inited;

  if (!str)
    return NULL;

  p = (unsigned char *)str;
  q = dest = malloc (strlen (str) * 6 + 1);

  if (!exmap_inited)
    {
      const unsigned char *e = json_exceptions;

      memset (exmap, 0, 256);
      while (*e)
        {
          exmap[*e] = 1;
          e++;
        }
      exmap_inited = 1;
    }

  while (*p)
    {
      if (exmap[*p])
        *q++ = *p;
      else
        {
          switch (*p)
            {
            case '\b':
              *q++ = '\\';
              *q++ = 'b';
              break;
            case '\f':
              *q++ = '\\';
              *q++ = 'f';
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
              if ((*p < ' ') || (*p >= 0177))
                {
                  const char *json_hex_chars = "0123456789abcdef";

                  *q++ = '\\';
                  *q++ = 'u';
                  *q++ = '0';
                  *q++ = '0';
                  *q++ = json_hex_chars[(*p) >> 4];
                  *q++ = json_hex_chars[(*p) & 0xf];
                }
              else
                *q++ = *p;
              break;
            }
        }
      p++;
    }

  *q = 0;
  return dest;
}

static inline ul_buffer_t *
_ul_buffer_ensure_size (ul_buffer_t *buffer, size_t size)
{
  if (buffer->alloc < size)
    {
      buffer->alloc += size * 2;
      buffer->msg = realloc (buffer->msg, buffer->alloc);
      if (!buffer->msg)
        return NULL;
    }
  return buffer;
}

ul_buffer_t *
ul_buffer_reset (ul_buffer_t *buffer)
{
  buffer->len = 1;
  _ul_buffer_ensure_size (buffer, 512);
  buffer->msg[0] = '{';
  return buffer;
}

ul_buffer_t *
ul_buffer_append (ul_buffer_t *buffer, const char *key, const char *value)
{
  char *k, *v;
  size_t lk, lv;

  k = _ul_str_escape (key);
  if (!k)
    return NULL;
  v = _ul_str_escape (value);
  if (!v)
    {
      free (k);
      return NULL;
    }

  lk = strlen (k);
  lv = strlen (v);

  buffer = _ul_buffer_ensure_size (buffer, buffer->len + lk + lv + 6);
  if (!buffer)
    {
      free (k);
      free (v);
      return NULL;
    }

  memcpy (buffer->msg + buffer->len, "\"", 1);
  memcpy (buffer->msg + buffer->len + 1, k, lk);
  memcpy (buffer->msg + buffer->len + 1 + lk, "\":\"", 3);
  memcpy (buffer->msg + buffer->len + 1 + lk + 3, v, lv);
  memcpy (buffer->msg + buffer->len + 1 + lk + 3 + lv, "\",", 2);
  buffer->len += lk + lv + 6;

  free (k);
  free (v);

  return buffer;
}

char *
ul_buffer_finalize (ul_buffer_t *buffer)
{
  if (buffer->msg[buffer->len - 1] == ',')
    buffer->msg[buffer->len - 1] = '}';
  else
    {
      if (!_ul_buffer_ensure_size (buffer, buffer->len + 1))
        return NULL;
      buffer->msg[buffer->len++] = '}';
      buffer->msg[buffer->len] = '\0';
    }
  return buffer->msg;
}
