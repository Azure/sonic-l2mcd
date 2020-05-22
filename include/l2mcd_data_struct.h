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

#ifndef __L2MCD_DATA_STRUCT__
#define __L2MCD_DATA_STRUCT__

#include "stdint.h"
#include <endian.h>
#include <sys/param.h>

#define UCHAR   unsigned char
#define USHORT  unsigned short
#define UINT    unsigned int
#define UINT8   unsigned char
#define UINT32 	unsigned int 
#define UINT64  unsigned long long
#define BYTE    unsigned char
#define DWORD   unsigned long
#define ULONG   unsigned long
#define UINT8   unsigned char
#define UINT            unsigned int
#define UINT64  unsigned long long
#define LONG            long
#define BOOL            unsigned char

typedef unsigned char   u_char;
typedef unsigned char   u_int8_t;
typedef unsigned char   uint8_t;
typedef unsigned short  uint16_t;
typedef unsigned int uint32_t;
typedef unsigned short  UINT16;
typedef UINT16 PORT_ID;
typedef int bool_t;
typedef unsigned int ifindex_t;

typedef UINT32 VRF_INDEX;

#endif //__L2MCD_DATA_STRUCT__
