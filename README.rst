libcee-syslog
=============

The libcee-syslog library serves two purposes: it's either a drop-in
replacement for the ``syslog()`` system call, in which case it turns
the default syslog messages into CEE-enhanced messages, with a
CEE-JSON payload, and some automatically discovered fields.

Or, it can be used as a stand-alone library, that provides a
``syslog()``-like API, with the ability to add arbitrary key-value
pairs to the resulting JSON payload.

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

Apart from the autotools, a C compiler, and json-c, there are no other
hard dependencies when building, except for a sufficiently modern
system.

Installation
------------

The library follows the usual autotools way of installation:

::

 $ git clone git://github.com/algernon/libcee-syslog.git
 $ cd libcee-syslog
 $ ./autogen.sh
 $ ./configure && make && make install

Usage
-----

The library can either be used as an LD_PRELOAD-able shared object, in
which case it overrides the system-supplied syslog() calls with its
own, or as a proper library. In the latter case, please see the
libcee-syslog(3) manual page for more information.

In the former case, using the library is as easy as setting LD_PRELOAD
prior to executing a program (if one wants to control this on a
per-program basis), or adding the path to the installed library to
``/etc/ld.so.preload``.

License
-------

This library is released under a two-clause BSD license, see the
LICENSE file for details.
