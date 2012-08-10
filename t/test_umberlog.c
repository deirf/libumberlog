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

/**
 * Test the umberlog defaults.
 */
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

/**
 * Test that openlog() is not overridden when using the linkable
 * library.
 */
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

/**
 * Test that using ul_openlog() does work, and sets up the program
 * identity appropriately.
 */
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

/**
 * Test that ul_openlog() will ignore any LOG_UL_* flags.
 */
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

/**
 * Test that setting LOG_UL_NOIMPLICIT will, indeed, turn off
 * automatically discovered fields.
 */
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

/**
 * Test turning off the timestamp.
 */
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

/**
 * Test that closelog() does not clear the previous flag settings.
 */
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

/**
 * Test adding additional fields.
 */
START_TEST (test_additional_fields)
{
  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_additional_fields", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "testing 1, 2, 3...",
                   "random_number", "%d", 42,
                   "random_string", "fourty-two",
                   NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "testing 1, 2, 3...");
  verify_value (jo, "random_number", "42");
  verify_value (jo, "random_string", "fourty-two");

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

/**
 * Test that discovering priorities work, and the implicit pid
 * overrides the explicit one.
 */
START_TEST (test_discover_priority)
{
  char *msg, *pid;
  struct json_object *jo;

  ul_openlog ("umberlog/test_discover_priority", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "testing 1, 2, 3...",
                   "pid", "%d", getpid () + 42,
                   NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "testing 1, 2, 3...");

  if (asprintf (&pid, "%d", getpid ()) == -1)
    abort ();
  verify_value (jo, "pid", pid);
  free (pid);

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

/**
 * Test for correct JSON escaping.
 */
START_TEST (test_json_escape)
{
  static const char control_chars[] =
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20";

  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_json_escape", 0, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "%s", __FUNCTION__,
                   "quotes", "Hi, \"quoted value\" speaking!",
                   "\"really\"", "yeah",
                   "control", "foo\nbar",
                   "utf8", "Árvíztűrő tükörfúrógép",
                   "junk", "\013foo",
                   "all_control", control_chars,
                   NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "quotes", "Hi, \"quoted value\" speaking!");
  verify_value (jo, "\"really\"", "yeah");
  verify_value (jo, "control", "foo\nbar");
  verify_value (jo, "utf8", "Árvíztűrő tükörfúrógép");
  verify_value (jo, "junk", "\013foo");
  verify_value (jo, "all_control", control_chars);

  json_object_put (jo);

  ul_closelog ();
}
END_TEST

/**
 * Test that using a FACILITY | PRIORITY combo with ul_format has the
 * desired result.
 */
START_TEST (test_facprio)
{
  char *msg;
  struct json_object *jo;

  msg = ul_format (LOG_LOCAL1 | LOG_DEBUG, "%s", __FUNCTION__,
                   NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "facility", "local1");
  verify_value (jo, "priority", "debug");

  json_object_put (jo);
}
END_TEST

#ifdef HAVE_PARSE_PRINTF_FORMAT
/**
 * Test parsing additional format strings, that are only supported if
 * we're under glibc.
 */
START_TEST (test_positional_params)
{
  char *msg;
  struct json_object *jo;

  ul_openlog ("umberlog/test_positional_params", 0, LOG_LOCAL0);

#define COMPLEX_FORMAT \
  "%3$*5$.*2$hhd , %1$Lf , %4$.3s , %4$s", 1.0L, 5, (char)100, "prefix", -8
#define COMPLEX_RESULT "00100    , 1.000000 , pre , prefix"
  msg = ul_format (LOG_DEBUG, COMPLEX_FORMAT,
                   "simple1", "value1",
                   "complex", COMPLEX_FORMAT,
                   "simple2", "value2",
                   NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", COMPLEX_RESULT);
  verify_value (jo, "simple1", "value1");
  verify_value (jo, "complex", COMPLEX_RESULT);
  verify_value (jo, "simple2", "value2");

  json_object_put (jo);

  ul_closelog ();
}
END_TEST
#endif

int
main (void)
{
  Suite *s;
  SRunner *sr;
  TCase *ft, *bt;
  int nfailed;

  s = suite_create ("Umberlog (linkable) functional testsuite");

  ft = tcase_create ("Basic tests");
  tcase_add_test (ft, test_defaults);
  tcase_add_test (ft, test_overrides);
  tcase_add_test (ft, test_ul_openlog);
  tcase_add_test (ft, test_ul_openlog_flag_ignore);
  tcase_add_test (ft, test_closelog);
  tcase_add_test (ft, test_no_implicit);
  tcase_add_test (ft, test_additional_fields);
  tcase_add_test (ft, test_discover_priority);
#ifdef HAVE_PARSE_PRINTF_FORMAT
  tcase_add_test (ft, test_positional_params);
#endif
  suite_add_tcase (s, ft);

  bt = tcase_create ("Bug tests");
  tcase_add_test (bt, test_json_escape);
  tcase_add_test (bt, test_facprio);
  suite_add_tcase (s, bt);

  sr = srunner_create (s);

  srunner_run_all (sr, CK_ENV);
  nfailed = srunner_ntests_failed (sr);
  srunner_free (sr);

  return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
