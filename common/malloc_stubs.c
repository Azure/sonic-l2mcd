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
#include <stdlib.h>
#include <string.h>
#include "l2mcd.h"

void *os_malloc(unsigned int size)
{
    void *ptr = malloc(size);
    return ptr;
}

void *os_malloc_zero(unsigned int size)
{
    void *ptr = malloc(size);
    if (ptr != NULL)
    {
        memset(ptr,0,size);
    }
    return ptr;
}

void os_free(void *ptr)
{
    free(ptr);
}

void *dy_malloc(unsigned int size)
{
    return (os_malloc(size));
}

void *dy_malloc_zero(unsigned int size)
{
    return (os_malloc_zero(size));
}

void dy_free(void *ptr)
{
    return (os_free(ptr));
}


