========
umberlog
========

--------------------------------------
CEE-enhanced syslog message generation
--------------------------------------

:Author: Gergely Nagy <algernon@balabit.hu>
:Date: 2012-03-23
:Manual section: 3
:Manual group: CEE-enhanced syslog Manual

SYNOPSIS
========

::
   
   #include <umberlog.h>

   void ul_openlog (const char *ident, int option, int facility);

   int ul_syslog (int priority, const char *format, ....);
   int ul_vsyslog (int priority, const char *format, va_list ap);

   void ul_legacy_syslog (int priority, const char *format, ...);
   void ul_legacy_vsyslog (int priority, const char *format, va_list ap);

   void ul_format (int priority, const char *format, ...);
   void ul_vformat (int priority, const char *format, va_list ap);

DESCRIPTION
===========

**ul_openlog()** (also aliased to **openlog()**) is a wrapper around
the original **openlog()** function, which opens a connection to the
system logger for a program. The updated version adds support for a
number of new option flags, described below.

**ul_legacy_syslog()** and **ul_legacy_vsyslog()** are both thin
layers over the original **syslog()** and **vsyslog()** functions, and
the library overrides the original functions with this two. The only
change these functions bring, are that the message they generate will
be a CEE-enhanced message, with a JSON payload. See below for an
explanation on what this means.

**ul_syslog()** and **ul_vsyslog()** are two new functions provided by
the library, that have similar interface to the legacy **syslog()**
functions, but they can be used to add arbitrary key-value pairs to
the emitted message. After the *msg_format* format string, and any
other parameters it refers to, there must be a NULL-terminated list of
*key*, *value format*, *format parameters*. Each of these pairs,
constructed from the *key* and the **printf(3)**-style *value format*
will be added to the generated message.

**ul_format()** and **ul_vformat()** do the same as the syslog
variants above, except the formatted payload is not sent to syslog,
but returned as a newly allocated string.

RETURN VALUE
============

When successful, **ul_syslog()** and **ul_vsyslog()** return zero,
while **ul_format()** and **ul_vformat()** return a character string.

On failure the former two will return non-zero, the latter two
**NULL**, and set *errno* appropriately.

CEE PAYLOAD
===========

All of the improved **syslog()** functions, the legacy and overridden
ones and the new ones too turn the original syslog message into a
CEE-enabled JSON payload, with the original message put into the *msg*
field, and any additional fields put into the same structure.

By default, unless the **LOG_UL_NODISCOVER** option flag is set, all
of these functions will also add a few automatically discovered fields
into the payload:

*pid*
  The process ID of the program, as returned by **getpid()** The value
  of this is - by default - determined at the time of calling
  **ul_openlog()**, but if caching is disabled, it will be rechecked
  every time.

*facility*, *priority*
  The syslog facility and priority as a text string.

*program*
  The identification set at the time of **ul_openlog()**.

*uid*, *gid*
  The user and group ID of the process, determined at **ul_openlog()**
  time by default, unless caching is disabled.

*host*
  The name of the originating host, determined at **ul_openlog()**
  time by default, using **gethostname()**.

*timestamp*
  High-precision timestamp, in textual format. Included by default,
  but can be controlled by the **LOG_UL_NOTIME** option flag at
  **ul_openlog()** time.

EXTRA OPTION FLAGS
==================

The *option* argument to **ul_openlog()** is an OR of any of the
original **openlog()** flags, and these:

LOG_UL_NODISCOVER
  Disable all automatic discovery, and only include the *message*,
  and any specified *key-value* pairs in the generated message.

LOG_UL_NOCACHE
  When automatic discovery is enabled, disable caching certain
  properties, that might change between the call to **openlog()** and
  the **ul_syslog()** invocation.

LOG_UL_NOCACHE_UID
  Disable the *uid* and *gid* caching when automatic discovery is
  enabled, but do cache the rest.
  
LOG_UL_NOTIME
  Do not add a high-precision timestamp to the generated message when
  automatic discovery is enabled.

EXAMPLES
========

::

    status = ul_syslog(LOG_NOTICE, "Logged in user: %s", username,
                       "service", "%s", service,
                       "auth-method", "%s", auth_method,
                       "sessionid", "%d", session_id,
                       NULL);

SEE ALSO
========
**syslog(1)**

COPYRIGHT
=========

This page is part of the *libumberlog* project, and is available under
the same 2-clause BSD license as the rest of the project.
