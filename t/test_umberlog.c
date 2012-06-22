#define _GNU_SOURCE 1

#include "umberlog.h"
#include <json.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#include <check.h>

static void
verify_value (struct json_object *jo, const char *key,
              const char *expected_value)
{
  struct json_object *o;
  const char *value;

  o = json_object_object_get (jo, key);

  ck_assert (o != NULL);

  value = json_object_get_string (o);

  ck_assert_str_eq (value, expected_value);
}

static void
verify_value_exists (struct json_object *jo, const char *key)
{
  struct json_object *o;

  o = json_object_object_get (jo, key);
  ck_assert_msg (o != NULL, "key '%s' does not exist", key);
}

static void
verify_value_missing (struct json_object *jo, const char *key)
{
  struct json_object *o;

  o = json_object_object_get (jo, key);
  assert (o == NULL);
}

static struct json_object *
parse_msg (const char *msg)
{
  struct json_object *jo;

  jo = json_tokener_parse (msg);
  assert (jo != NULL);

  return jo;
}

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

START_TEST (test_no_discover)
{
  char *msg;
  struct json_object *jo;

  openlog ("umberlog/test_no_discover", LOG_UL_NODISCOVER, LOG_LOCAL0);

  msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "hello, I'm test_no_discover!");
  verify_value_missing (jo, "facility");
  verify_value_missing (jo, "priority");
  verify_value_missing (jo, "program");
  verify_value_missing (jo, "pid");
  verify_value_missing (jo, "uid");
  verify_value_missing (jo, "gid");
  verify_value_missing (jo, "host");
  verify_value_missing (jo, "timestamp");

  json_object_put (jo);

  closelog ();
}
END_TEST

START_TEST (test_additional_fields)
{
  char *msg;
  struct json_object *jo;

  openlog ("umberlog/test_additional_fields", 0, LOG_LOCAL0);

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

  closelog ();
}
END_TEST

START_TEST (test_discover_priority)
{
  char *msg, *pid;
  struct json_object *jo;

  openlog ("umberlog/test_discover_priority", 0, LOG_LOCAL0);

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

  closelog ();
}
END_TEST

START_TEST (test_no_timestamp)
{
  char *msg;
  struct json_object *jo;

  openlog ("umberlog/test_no_timestamp", LOG_UL_NOTIME, LOG_LOCAL0);

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

  closelog ();
}
END_TEST

START_TEST (test_json_escape)
{
  static const char control_chars[] =
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20";

  char *msg;
  struct json_object *jo;

  openlog ("umberlog/test_json_escape", LOG_UL_NODISCOVER, LOG_LOCAL0);

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

  closelog ();
}
END_TEST

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

START_TEST (test_closelog)
{
  char *msg;
  struct json_object *jo;

  openlog ("umberlog/test_closelog", LOG_UL_NODISCOVER, LOG_LOCAL0);
  closelog ();

  msg = ul_format (LOG_LOCAL1 | LOG_DEBUG, "%s", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "facility", "local1");

  json_object_put (jo);
}
END_TEST

int
main (void)
{
  Suite *s;
  SRunner *sr;
  TCase *ft, *bt;
  int nfailed;

  s = suite_create ("Umberlog functional testsuite");

  ft = tcase_create ("Basic tests");
  tcase_add_test (ft, test_simple);
  tcase_add_test (ft, test_no_discover);
  tcase_add_test (ft, test_additional_fields);
  tcase_add_test (ft, test_discover_priority);
  tcase_add_test (ft, test_no_timestamp);
  suite_add_tcase (s, ft);

  bt = tcase_create ("Bug tests");
  tcase_add_test (bt, test_json_escape);
  tcase_add_test (bt, test_facprio);
  tcase_add_test (bt, test_closelog);
  suite_add_tcase (s, bt);

  sr = srunner_create (s);

  srunner_run_all (sr, CK_ENV);
  nfailed = srunner_ntests_failed (sr);
  srunner_free (sr);

  return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
