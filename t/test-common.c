#define _GNU_SOURCE 1

#include <json.h>
#include <assert.h>
#include <check.h>

void
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

void
verify_value_differs (struct json_object *jo, const char *key,
                      const char *unexpected_value)
{
  struct json_object *o;
  const char *value;

  o = json_object_object_get (jo, key);

  ck_assert (o != NULL);

  value = json_object_get_string (o);

  ck_assert_str_ne (value, unexpected_value);
}

void
verify_value_exists (struct json_object *jo, const char *key)
{
  struct json_object *o;

  o = json_object_object_get (jo, key);
  ck_assert_msg (o != NULL, "key '%s' does not exist", key);
}

void
verify_value_missing (struct json_object *jo, const char *key)
{
  struct json_object *o;

  o = json_object_object_get (jo, key);
  assert (o == NULL);
}

struct json_object *
parse_msg (const char *msg)
{
  struct json_object *jo;

  jo = json_tokener_parse (msg);
  assert (jo != NULL);

  return jo;
}
