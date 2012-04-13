LUL_CURRENT			= 0
LUL_REVISION			= 0
LUL_AGE				= 0

lib_LTLIBRARIES			= libumberlog.la
libumberlog_la_LDFLAGS		= -Wl,--version-script,${srcdir}/libumberlog.ld

libumberlog_la_SOURCES		= umberlog.c umberlog.h buffer.c buffer.h

libumberlog_includedir		= $(includedir)
libumberlog_include_HEADERS	= umberlog.h

pkgconfigdir			= $(libdir)/pkgconfig
pkgconfig_DATA			= libumberlog.pc

EXTRA_DIST			= umberlog.rst libumberlog.ld
