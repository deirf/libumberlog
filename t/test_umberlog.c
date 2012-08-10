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

START_TEST (test_defaults)
{
  char *msg;
  struct json_object *jo;

  char host[_POSIX_HOST_NAME_MAX + 1];

  ul_openlog ("umberlog/test_defaults", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  gethostname (host, _POSIX_HOST_NAME_MAX);

  verify_value (jo, "msg", "hello, I'm test_defaults!");
  verify_value (jo, "facility", "local0");
  verify_value (jo, "priority", "debug");
  verify_value (jo, "program", "umberlog/test_defaults");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_exists (jo, "timestamp");
  verify_value (jo, "host", host);

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

START_TEST (test_overrides)
{
  char *msg;
  struct json_object *jo;
  char host[_POSIX_HOST_NAME_MAX + 1];

  openlog ("umberlog/test_overrides", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  gethostname (host, _POSIX_HOST_NAME_MAX);

  verify_value (jo, "msg", "hello, I'm test_overrides!");
  /* Default facility is user, and since we did not catch openlog, it
     should not change. */
  verify_value (jo, "facility", "user");
  verify_value (jo, "priority", "debug");
  /* The program is also caught by openlog(), so we'll get the
     default back, unless we use ul_openlog(). */
  verify_value (jo, "program", "test_umberlog");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_exists (jo, "timestamp");
  verify_value (jo, "host", host);

  json_object_put (jo);

  closelog ();
}
END_TEST

START_TEST (test_ul_openlog)
{
  char *msg;
  struct json_object *jo;
  char host[_POSIX_HOST_NAME_MAX + 1];

  ul_openlog ("umberlog/test_ul_openlog", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  gethostname (host, _POSIX_HOST_NAME_MAX);

  verify_value (jo, "msg", "hello, I'm test_ul_openlog!");
  verify_value (jo, "facility", "local0");
  verify_value (jo, "priority", "debug");
  verify_value (jo, "program", "umberlog/test_ul_openlog");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_exists (jo, "timestamp");
  verify_value (jo, "host", host);

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

START_TEST (test_ul_openlog_flag_ignore)
{
  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_ul_openlog_flag_ignore", LOG_UL_NOIMPLICIT,
              LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_exists (jo, "host");

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

START_TEST (test_no_implicit)
{
  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_no_implicit", 0, LOG_LOCAL0);
  ul_set_log_flags (LOG_UL_NOIMPLICIT);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "hello, I'm test_no_implicit!");
  verify_value_missing (jo, "facility");
  verify_value_missing (jo, "priority");
  verify_value_missing (jo, "program");
  verify_value_missing (jo, "pid");
  verify_value_missing (jo, "uid");
  verify_value_missing (jo, "gid");
  verify_value_missing (jo, "host");
  verify_value_missing (jo, "timestamp");

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

START_TEST (test_no_timestamp)
{
  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_no_timestamp", 0, LOG_LOCAL0);
  ul_set_log_flags (LOG_UL_NOTIME);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "hello, I'm test_no_timestamp!");
  verify_value (jo, "facility", "local0");
  verify_value (jo, "priority", "debug");
  verify_value (jo, "program", "umberlog/test_no_timestamp");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");
  verify_value_missing (jo, "timestamp");
  verify_value_exists (jo, "host");

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

START_TEST (test_closelog)
{
  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_closelog", 0, LOG_LOCAL0);
  ul_set_log_flags (LOG_UL_NOIMPLICIT);
  ul_closelog ();

  msg = ul_format (LOG_DEBUG, "%s", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value_missing (jo, "facility");

  json_object_put (jo);

  ul_openlog ("umberlog/test_closelog", 0, LOG_LOCAL0);
  ul_closelog ();

  msg = ul_format (LOG_DEBUG, "%s", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value_missing (jo, "facility");
  verify_value_missing (jo, "program");

  verify_value_missing (jo, "pid");
  verify_value_missing (jo, "uid");
  verify_value_missing (jo, "gid");
  verify_value_missing (jo, "host");

  json_object_put (jo);
}
END_TEST

int
main (void)
{
  Suite *s;
  SRunner *sr;
  TCase *ft;
  int nfailed;

  s = suite_create ("Umberlog (linkable) functional testsuite");

  ft = tcase_create ("Basic tests");
  tcase_add_test (ft, test_defaults);
  tcase_add_test (ft, test_overrides);
  tcase_add_test (ft, test_ul_openlog);
  tcase_add_test (ft, test_ul_openlog_flag_ignore);
  tcase_add_test (ft, test_closelog);
  tcase_add_test (ft, test_no_implicit);
  suite_add_tcase (s, ft);

  sr = srunner_create (s);

  srunner_run_all (sr, CK_ENV);
  nfailed = srunner_ntests_failed (sr);
  srunner_free (sr);

  return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
