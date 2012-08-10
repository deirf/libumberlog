if ENABLE_TESTS
TESTS				= test_umberlog_preload test_umberlog test_perf
check_PROGRAMS			= ${TESTS}

AM_CFLAGS			= -I$(top_srcdir)/lib @JSON_CFLAGS@ @CHECK_CFLAGS@
AM_LDFLAGS			= -no-install
LDADD				= @JSON_LIBS@ @CHECK_LIBS@

check_LTLIBRARIES		= libultest.la
libultest_la_SOURCES		= test-common.c test-common.h

test_umberlog_preload_LDADD	= ${LDADD} $(top_builddir)/lib/libumberlog_preload.la libultest.la
test_umberlog_LDADD		= ${LDADD} $(top_builddir)/lib/libumberlog.la libultest.la
test_perf_LDADD			= ${LDADD} $(top_builddir)/lib/libumberlog.la libultest.la
endif
