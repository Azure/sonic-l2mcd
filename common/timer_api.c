/*
 * Copyright 2019 Broadcom.  The term “Broadcom” refers to Broadcom Inc. and/or
 * its subsidiaries.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sys/time.h>
#include <time.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <error.h>

unsigned long long l3_ref_time;
unsigned long g_timetick_freq;
unsigned long g_timebase_freq;


/* Returns the value w.r.t reference time in 1ms frequency */
unsigned long long sys_get_millisecond(void)
{
    unsigned long long current;
    unsigned long long current_time;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        current = ((((unsigned long long)ts.tv_sec) * 1000) + (((unsigned long long)ts.tv_nsec)/1000000));
    } else {
        current=0;
        perror("sys_get_millisecond");
    }
    current_time= (unsigned long long)((current - l3_ref_time));
    return current_time;
}

/* Returns the value w.r.t reference time in 50ms frequency */
unsigned long sys_get_timeticks()
{
    unsigned long current_time50;
    current_time50= (unsigned long)((sys_get_millisecond())/50);
    return current_time50;
}

/* Initialise the reference time in milli, all further calls to time will be from the reference time */
unsigned long long sys_get_reftime(void)
{
    struct timespec ts;
    int errno=0;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        l3_ref_time = ((((unsigned long long)ts.tv_sec) * 1000) + (((unsigned long long)ts.tv_nsec)/1000000));
    } else {
        l3_ref_time=0;
        perror("sys_get_reftime");
        return errno;
    }
    return 0;
}

int l3_time_freq_init(void)
{
    int rc;
    g_timetick_freq = 20;
    g_timebase_freq = 1000;
    rc = sys_get_reftime();
    if (rc < 0) {
        printf("sys_get_reftime failed (error %d)\n", rc);
        return (-1);
    }
    return 0;
}

unsigned long long read_long_time_base()
{
    return sys_get_millisecond();
}
