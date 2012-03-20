#define _GNU_SOURCE 1

#include "cee-syslog.h"
#include <json.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

static void
verify_value (struct json_object *jo, const char *key,
              const char *expected_value)
{
  struct json_object *o;
  const char *value;

  o = json_object_object_get (jo, key);

  assert (o != NULL);

  value = json_object_get_string (o);

  assert (value != NULL);
  assert (strcmp (value, expected_value) == 0);
}

static void
verify_value_exists (struct json_object *jo, const char *key)
{
  struct json_object *o;

  o = json_object_object_get (jo, key);
  assert (o != NULL);
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

static void
test_simple (void)
{
  char *msg;
  struct json_object *jo;

  openlog ("cee-syslog/test_simple", 0, LOG_LOCAL0);

  msg = cee_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "hello, I'm test_simple!");
  verify_value (jo, "facility", "local0");
  verify_value (jo, "priority", "debug");
  verify_value (jo, "program", "cee-syslog/test_simple");
  verify_value_exists (jo, "pid");
  verify_value_exists (jo, "uid");
  verify_value_exists (jo, "gid");

  json_object_put (jo);

  closelog ();
}

static void
test_no_discover (void)
{
  char *msg;
  struct json_object *jo;

  openlog ("cee-syslog/test_no_discover", LOG_CEE_NODISCOVER, LOG_LOCAL0);

  msg = cee_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "hello, I'm test_no_discover!");
  verify_value_missing (jo, "facility");
  verify_value_missing (jo, "priority");
  verify_value_missing (jo, "program");
  verify_value_missing (jo, "pid");
  verify_value_missing (jo, "uid");
  verify_value_missing (jo, "gid");

  json_object_put (jo);

  closelog ();
}

static void
test_additional_fields (void)
{
  char *msg;
  struct json_object *jo;

  openlog ("cee-syslog/test_additional_fields", 0, LOG_LOCAL0);

  msg = cee_format (LOG_DEBUG, "testing 1, 2, 3...",
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

static void
test_discover_priority (void)
{
  char *msg, *pid;
  struct json_object *jo;

  openlog ("cee-syslog/test_discover_priority", 0, LOG_LOCAL0);

  msg = cee_format (LOG_DEBUG, "testing 1, 2, 3...",
                    "pid", "%d", getpid () + 42,
                    NULL);
  jo = parse_msg (msg);
  free (msg);

  verify_value (jo, "msg", "testing 1, 2, 3...");

  asprintf (&pid, "%d", getpid ());
  verify_value (jo, "pid", pid);
  free (pid);

  json_object_put (jo);

  closelog ();
}

int
main (void)
{
  test_simple ();
  test_no_discover ();
  test_additional_fields ();
  test_discover_priority ();

  return 0;
}
