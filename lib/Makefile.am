LUL_CURRENT			= 2
LUL_REVISION			= 0
LUL_AGE				= 1

lib_LTLIBRARIES			= libumberlog.la
libumberlog_la_LDFLAGS		= -Wl,--version-script,${srcdir}/libumberlog.ld \
				  -version-info ${LUL_CURRENT}:${LUL_REVISION}:${LUL_AGE}

libumberlog_la_SOURCES		= umberlog.c umberlog.h buffer.c buffer.h
libumberlog_la_LIBADD		= -lpthread

libumberlog_includedir		= $(includedir)
libumberlog_include_HEADERS	= umberlog.h

pkgconfigdir			= $(libdir)/pkgconfig
pkgconfig_DATA			= libumberlog.pc

EXTRA_DIST			= umberlog.rst libumberlog.ld

if ENABLE_MANS
man3_MANS			= umberlog.3
CLEANFILES			= umberlog.3
EXTRA_DIST			+= umberlog.3

umberlog.3: umberlog.rst
	$(AM_V_GEN) $(RST2MAN) $< $@
endif
