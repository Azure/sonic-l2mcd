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
#define INTERFACE_NAMSIZ 64

#define PORT_INDEX_INVALID      16384
#define IPV6_INTERFACE_ID       PORT_ID
typedef UINT32 VLAN_ID;
typedef UINT32 IP_ADDRESS;
#define NONE    0
typedef enum BOOLEAN
{
    TRUE= 1,
    FALSE = 0
} BOOLEAN;

#if (__BYTE_ORDER == __BIG_ENDIAN)

        #define BIG_ENDIAN_CONSTANT_ULONG(ulong) (ulong)
        #define BIG_ENDIAN_CONSTANT(ushort) (ushort)
        #define NET_ORDER_SHORT_CONSTANT(ushort) (ushort)
        #define NET_ORDER_LONG_CONSTANT(ulong) (ulong)

        #define swap(a)              (a)
        #define swap_long(a)         (a)

        #define host_to_net_short(a) (a)
        #define host_to_net_long(a)  (a)
        #define net_to_host_short(a) (a)
        #define net_to_host_long(a)  (a)

#ifndef __GNUC__
        #define htons(a)             host_to_net_short(a)
        #define htonl(a)             host_to_net_long(a)
        #define ntohs(a)             net_to_host_short(a)
        #define ntohl(a)             net_to_host_long(a)
#endif

#else

        #define BIG_ENDIAN_CONSTANT_ULONG(ulong)        \
                ((((ulong) << 24) & 0xff000000L)                \
                |(((ulong) << 8) & 0x00ff0000L)                 \
                |(((ulong) >> 8) & 0x0000ff00L)                 \
                |(((ulong) >> 24) & 0x000000ffL))
        #define BIG_ENDIAN_CONSTANT(ushort)                     \
                ((((ushort) & 0x00ff) << 8)                             \
                |((ushort) >> 8))
        #define NET_ORDER_SHORT_CONSTANT(ushort)        \
                ((((ushort) & 0x00ff) << 8)                             \
                |((ushort) >> 8))
        #define NET_ORDER_LONG_CONSTANT(ulong)          \
                ((((ulong) & 0x000000ffL) << 24)                \
                |(((ulong) & 0x0000ff00L) << 8)                 \
                |(((ulong) & 0x00ff0000L) >> 8)                 \
                |((ulong) >> 24))

        /* convutls.c */
        extern USHORT host_to_net_short(USHORT a);
        extern ULONG host_to_net_long(ULONG a);
        extern USHORT net_to_host_short(USHORT a);
        extern ULONG net_to_host_long(ULONG a);
        extern USHORT swap(USHORT a);
        extern ULONG swap_long(ULONG a);

		  #define host_to_net_short htons
		  #define host_to_net_long htonl
		  #define net_to_host_short ntohs
		  #define net_to_host_long ntohl
#endif

#ifndef __GNUC__
		  #error
        #define htons(a)             host_to_net_short(a)
        #define htonl(a)             host_to_net_long(a)
        #define ntohs(a)             net_to_host_short(a)
        #define ntohl(a)             net_to_host_long(a)
#endif

UINT16 reverse_bits16(UINT16 x);
UINT32 reverse_bits32(UINT32 x);
#define GLOBAL  extern
#define BYTE_ENUM(enum_name) BYTE


typedef union ip6_union_ipv6_address {
	UINT8	address8[16];
	UINT16	address16[8];
	UINT32	address32[4];
} IP6_UNION_IPV6_ADDRESS;

typedef struct IP6_IPV6_ADDRESS {
		IP6_UNION_IPV6_ADDRESS address;
} IP6_IPV6_ADDRESS;

#define IPV6_ADDRESS IP6_IPV6_ADDRESS

typedef UINT16  vlan_id_t;
typedef struct MAC_ADDRESS
{
	UINT32							_ulong;
	UINT16							_ushort;
} MAC_ADDRESS;

typedef UINT32 VRF_INDEX;

#endif //__L2MCD_DATA_STRUCT__
