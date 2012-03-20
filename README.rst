libcee-syslog
=============

The libcee-syslog library serves two purposes: it's either a drop-in
replacement for the ``syslog()`` system call, in which case it turns
the default syslog messages into CEE-enhanced messages, with a
CEE-JSON payload, and some automatically discovered fields. Or, it can
be used as a stand-alone library, that provides a ``syslog()``-like
API, with the ability to add arbitrary key-value pairs to the
resulting JSON payload.

Features
--------

libcee-syslog is supposed to be a thin layer, that provides a few
benefits over legacy ``syslog()``, within reason, and with
limitations.

* It overrides **openlog()**, to be able to store extra flags, and
  cache some stuff, if so need be. Currently, it caches the *pid* and
  the *ident*.
* It overrides **syslog()** (and **vsyslog()**), but does NOT extend
  those APIs. It merely turns a legacy syslog message into something
  that has a CEE payload, and unless turned off, it adds a few
  automatically discovered fields.
* It provides **cee_syslog()** (and **cee_vsyslog()**), which do the
  same as the `syslog()` call, have the same auto-discovery mechanism,
  but they also allow adding arbitrary key-value pairs.
* It provides **cee_format()** (and **cee_vformat()**), which do the
  same as the syslog calls, except the result is a newly allocated
  string, that does not have a ``@cee:`` prefix.

Non-goals
---------

* It is not a goal to support anything else but ``syslog()`` payload.
* It is not a goal to go to great lengths to discover things about the
  running process: only a few things that are easily available, no
  matter how reliable this information may be.
* It is not a goal to support complex values, or anything other than
  plain C strings.
  
Requirements
------------

Apart from the autotools and a C compiler, there are no other hard
dependencies when building, except for a sufficiently modern system.

Installation
------------

The library follows the usual autotools way of installation:

::

 $ git clone git://github.com/algernon/libcee-syslog.git
 $ cd libcee-syslog
 $ ./autogen.sh
 $ ./configure && make && make install

License
-------

This library is released under a two-clause BSD license, see the
LICENSE file for details.
