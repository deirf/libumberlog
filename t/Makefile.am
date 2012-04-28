if ENABLE_TESTS
TESTS		= test_umberlog test_perf
check_PROGRAMS	= ${TESTS}

AM_CFLAGS = -I$(top_srcdir)/lib @JSON_CFLAGS@ @CHECK_CFLAGS@
LDADD = $(top_builddir)/lib/libumberlog.la @JSON_LIBS@ @CHECK_LIBS@
endif
