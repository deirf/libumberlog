dnl Process this file with autoconf to produce a configure script.
dnl

AC_INIT(libumberlog, 0.1.1, algernon@balabit.hu, libumberlog, https://github.com/algernon/libumberlog)
AM_INIT_AUTOMAKE([1.9 tar-ustar])

dnl ***************************************************************************
dnl dependencies

JSON_C_MIN_VERSION="0.7"

dnl ***************************************************************************
dnl Initial setup

AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_CONFIG_HEADER(config.h)

dnl ***************************************************************************
dnl Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB
AM_PROG_CC_STDC
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG
LT_INIT([shared])

dnl ***************************************************************************
dnl Miscellanneous headers
dnl ***************************************************************************

AC_HEADER_STDC

dnl ***************************************************************************
dnl Header checks
dnl ***************************************************************************
AC_CHECK_HEADERS([syslog.h dlfcn.h limits.h])

dnl ***************************************************************************
dnl Checks for libraries
AC_CHECK_FUNCS([gethostname strdup __syslog_chk])

dnl The dlopen() function is in the C library for *BSD and in
dnl libdl on GLIBC-based systems
AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen() function])
])

dnl Similarly, clock_gettime is in the C library on *BSD, and in librt
dnl on GLIBC-based systems.
AC_SEARCH_LIBS([clock_gettime], [rt], [], [
  AC_MSG_ERROR([unable to find the clock_gettime() function])
])

dnl ***************************************************************************
dnl JSON-C headers/libraries
dnl ***************************************************************************
PKG_CHECK_MODULES(JSON, json >= $JSON_C_MIN_VERSION,,)

dnl ***************************************************************************
dnl misc features to be enabled
dnl ***************************************************************************
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_UID_T

AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [package name])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [version number])

AC_OUTPUT(
	Makefile
        data/Makefile
        lib/Makefile
	lib/libumberlog.pc
        t/Makefile
)
