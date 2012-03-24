What?
=====

The libumberlog library serves two purposes: it's either a drop-in
replacement for the ``syslog()`` system call, in which case it turns
the default syslog messages into CEE-enhanced messages, with a
CEE-JSON payload, and some automatically discovered fields.

Or, it can be used as a stand-alone library, that provides a
``syslog()``-like API, with the ability to add arbitrary key-value
pairs to the resulting JSON payload.

Why?
====

The primary goal of the library is to smoothly introduce people -
administrators and developers alike - to structured logging. The
library aims to not only replace the traditional ``syslog()`` system
call, but to extend it too.

The extensions (unless turned off) provide information not normally
available via traditional syslog, such as a high-resolution timestamp,
making them just that more useful.

How?
====

All of this is accomplished in a way that allows for
**LD_PRELOAD**-ing the library, either on a case-by-case basis, or
system-wide, and seamlessly transform traditional syslog messages,
without any further work required.

Even better, the library provides new functions, that are modelled
after the traditional ``syslog()`` API, but provide a few
improvements, such as the ability to add arbitrary key-value pairs to
the structured message, and reasonable error handling.

More details
============

An example
----------

One does wonder, how an example might look like, we're happy to
oblige, and show one (word wrapped, for an easier read):

SSH Login::

  Mar 24 12:01:34 localhost sshd[12590]: @cee:{
      "msg": "Accepted publickey for algernon from 127.0.0.1 port 55519 ssh2",
      "pid": "12590", "facility": "auth", "priority": "info",
      "program": "sshd", "uid": "0", "gid": "0",
      "host": "hadhodrond", "timestamp": "2012-03-24T12:01:34.236987887+0100" }

Requirements
------------

Apart from the autotools, a C compiler, and `json\-c`_, there are no
other hard dependencies when building, except for a sufficiently
modern system.

.. _json\-c: http://oss.metaparadigm.com/json-c/

Installation
------------

The library follows the usual autotools way of installation:

::

 $ git clone git://github.com/algernon/libumberlog.git
 $ cd libumberlog
 $ ./autogen.sh
 $ ./configure && make && make install

Usage
-----

The library can either be used as an LD_PRELOAD-able shared object, in
which case it overrides the system-supplied ``syslog()`` calls with
its own, or as a proper library. In the latter case, please see the
`API documentation`_ for more information.

In the former case, using the library is as easy as setting
**LD_PRELOAD** prior to executing a program (if one wants to control
this on a per-program basis), or adding the path to the installed
library to ``/etc/ld.so.preload``.

.. _API documentation: http://algernon.github.com/libumberlog/umberlog.html

Non-goals
---------

* It is not a goal to support anything else but ``syslog()`` payload.
* It is not a goal to go to great lengths to discover things about the
  running process: only a few things that are easily available, no
  matter how reliable this information may be.
* It is not a goal to support complex values, or anything other than
  plain C strings.
  
License
-------

This library is released under a two-clause BSD license, see the
`LICENSE`_ file for details.

.. _LICENSE: https://raw.github.com/algernon/libumberlog/master/LICENSE
