LCS_CURRENT			= 0
LCS_REVISION			= 0
LCS_AGE				= 0

lib_LTLIBRARIES			= libcee-syslog.la
libcee_syslog_la_LIBADD		= @JSON_LIBS@ -ldl -lrt
libcee_syslog_la_CFLAGS		= @JSON_CFLAGS@

libcee_syslog_la_SOURCES	= \
	cee-syslog.c cee-syslog.h

libcee_syslog_includedir	= $(includedir)/cee
libcee_syslog_include_HEADERS	= \
	cee-syslog.h

pkgconfigdir			= $(libdir)/pkgconfig
pkgconfig_DATA			= libcee-syslog.pc

man3_MANS			= cee_syslog.3
