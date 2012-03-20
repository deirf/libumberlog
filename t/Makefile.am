TESTS		= test_cee_format
check_PROGRAMS	= ${TESTS}

AM_CFLAGS = -I$(top_srcdir)/lib @JSON_CFLAGS@
LDADD = $(top_builddir)/lib/libcee-syslog.la @JSON_LIBS@
