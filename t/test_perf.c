#define _GNU_SOURCE 1

#include "umberlog.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static inline struct timespec
ts_diff (struct timespec start, struct timespec end)
{
  struct timespec temp;
  if ((end.tv_nsec - start.tv_nsec) < 0)
    {
      temp.tv_sec = end.tv_sec - start.tv_sec - 1;
      temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    }
  else
    {
      temp.tv_sec = end.tv_sec - start.tv_sec;
      temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
  return temp;
}

static inline void
test_perf_simple (int flags, unsigned long cnt)
{
  char *msg;
  unsigned long i;
  struct timespec st, et, dt;
  const char *fls;

  ul_openlog ("umberlog/test_perf_simple", 0, LOG_LOCAL0);
  ul_set_log_flags (flags);

  clock_gettime (CLOCK_MONOTONIC, &st);
  for (i = 0; i < cnt; i++)
    {
      msg = ul_format (LOG_DEBUG, "hello, I'm %s!", __FUNCTION__, NULL);
      free (msg);
    }
  clock_gettime (CLOCK_MONOTONIC, &et);

  ul_closelog ();

  dt = ts_diff (st, et);

  if (flags & LOG_UL_NOIMPLICIT)
    fls = "no-implicit";
  else if (flags & LOG_UL_NOTIME)
    fls = "no-time";
  else
    fls = "discover";

  printf ("# test_perf_simple(%s, %lu): %lu.%lus\n",
          fls, cnt,
          dt.tv_sec, dt.tv_nsec);
}

int
main (void)
{
  test_perf_simple (0, 100000);
  test_perf_simple (0, 1000000);

  test_perf_simple (LOG_UL_NOIMPLICIT, 100000);
  test_perf_simple (LOG_UL_NOIMPLICIT, 1000000);

  test_perf_simple (LOG_UL_NOTIME, 100000);
  test_perf_simple (LOG_UL_NOTIME, 1000000);

  return 0;
}
