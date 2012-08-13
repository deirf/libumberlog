#ifndef UMBERLOG_TEST_COMMON_H
#define UMBERLOG_TEST_COMMON_H 1

#include <json.h>

void verify_value (struct json_object *jo, const char *key,
                   const char *expected_value);
void verify_value_differs (struct json_object *jo, const char *key,
                           const char *unexpected_value);
void verify_value_exists (struct json_object *jo, const char *key);
void verify_value_missing (struct json_object *jo, const char *key);

struct json_object *parse_msg (const char *msg);
#endif
