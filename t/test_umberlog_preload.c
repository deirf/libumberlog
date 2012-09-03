#define _GNU_SOURCE 1

#include "umberlog.h"
#include "config.h"
#include "test-common.h"
#include <json.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#include <check.h>


/** This must be the first test!
 *
 * This check verifies the openlog() defaults, and that additional
 * fields are properly added.
 */
START_TEST (test_openlog_defaults)
{
  char *msg;
  struct json_object *jo;

  /* No openlog */

  msg = ul_format (LOG_ALERT, "message", NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "facility", "user");
#ifdef HAVE_PROGRAM_INVOCATION_SHORT_NAME
  verify_value (jo, "program", "test_umberlog_preload");
#else
  verify_value_missing (jo, "program");
#endif
  verify_value_differs (jo, "pid", "0");
  if (getuid () != 0)
    verify_value_differs (jo, "uid", "0");
  if (getgid () != 0)
    verify_value_differs (jo, "gid", "0");
  verify_value_differs (jo, "host", "");

  json_object_put (jo);

  closelog ();
}
END_TEST

/**
 * This verifies that adding any LOG_UL_* flags to openlog() will have
 * no effect.
 */
START_TEST (test_openlog_flags)
{
  char *msg;
  struct json_object *jo;
  char host[_POSIX_HOST_NAME_MAX + 1];

  openlog ("umberlog/test_openlog_flags", LOG_UL_NOIMPLICIT, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  gethostname (host, _POSIX_HOST_NAME_MAX);

  verify_value (jo, "msg", "hello, I'm test_openlog_flags!");
  verify_value (jo, "facility", "local0");
  verify_value (jo, "priority", "debug");
  verify_value (jo, "program", "umberlog/test_openlog_flags");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_exists (jo, "timestamp");
  verify_value (jo, "host", host);

  json_object_put (jo);

  closelog ();
}
END_TEST

/**
 * A simple test that options that should be respected, are respected.
 */
START_TEST (test_simple)
{
  char *msg;
  struct json_object *jo;
  char host[_POSIX_HOST_NAME_MAX + 1];

  openlog ("umberlog/test_simple", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  gethostname (host, _POSIX_HOST_NAME_MAX);

  verify_value (jo, "msg", "hello, I'm test_simple!");
  verify_value (jo, "facility", "local0");
  verify_value (jo, "priority", "debug");
  verify_value (jo, "program", "umberlog/test_simple");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_exists (jo, "timestamp");
  verify_value (jo, "host", host);

  json_object_put (jo);

  closelog ();
}
END_TEST

int
main (void)
{
  Suite *s;
  SRunner *sr;
  TCase *ft, *bt;
  int nfailed;

  s = suite_create ("Umberlog (LD_PRELOAD) functional testsuite");

#if DEFAULT_LOG_FLAGS == LOG_UL_ALL
  ft = tcase_create ("Basic tests");
  tcase_add_test (ft, test_openlog_defaults);
  tcase_add_test (ft, test_openlog_flags);
  tcase_add_test (ft, test_simple);
  suite_add_tcase (s, ft);
#endif

  sr = srunner_create (s);

  srunner_run_all (sr, CK_ENV);
  nfailed = srunner_ntests_failed (sr);
  srunner_free (sr);

  return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
