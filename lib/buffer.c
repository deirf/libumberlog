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
  size_t lk, lv;

  lk = strlen (key);
  lv = strlen (value);

  buffer = _ul_buffer_ensure_size (buffer, buffer->len + lk + lv + 6);
  if (!buffer)
    return NULL;

  /* FIXME: Escpae stuff here */

  memcpy (buffer->msg + buffer->len, "\"", 1);
  memcpy (buffer->msg + buffer->len + 1, key, lk);
  memcpy (buffer->msg + buffer->len + 1 + lk, "\":\"", 3);
  memcpy (buffer->msg + buffer->len + 1 + lk + 3, value, lv);
  memcpy (buffer->msg + buffer->len + 1 + lk + 3 + lv, "\",", 2);
  buffer->len += lk + lv + 6;

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
