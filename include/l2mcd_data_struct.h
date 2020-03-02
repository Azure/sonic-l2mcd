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


#define GENERIC_POOL_NUMBER 64

#define GENPOOL_ALLOC_MAGIC     0xDEADCAFE
#define GENPOOL_FREE_MAGIC      0xFEEDCAFE
#define POOL_SIZE_HUGE_NUMBER 2000000000

#define MEM_SIZE_8M   0x800000
#define MEM_SIZE_4M   0x400000
#define MEM_SIZE_2M   0x200000
#define MEM_SIZE_1M   0x100000
#define MEM_SIZE_512K 0x080000
#define MEM_SIZE_256K 0x040000
#define MEM_SIZE_128K 0x020000
#define MEM_SIZE_64K  0x010000
#define MEM_SIZE_32K  0x008000
#define MEM_SIZE_16K  0x004000
#define MEM_SIZE_8K   0x002000
#define MEM_SIZE_4K   0x001000
#define MEM_SIZE_2K   0x000800
#define MEM_SIZE_1K   0x000400

#define STACK_DEPTH 28

enum _GENERIC_POOL_FLAGS
{
	GENERIC_POOL_NO_GROW = 0x1,
	GENERIC_POOL_DONT_ALLOC = 0x2, // Don't allocate it initially
// if NO_GROW=0, then grow it linearly, 
// otherwise it is about 1.5 times
	GENERIC_POOL_LINEAR_GROW = 0x4,
	GENERIC_POOL_MEMCHK_ON = 0x8         // Enable magic word for each unit of a pool
};

struct MEM_ALLOCATOR;

typedef void *(*ALLOC_FUNC)(unsigned int size, struct MEM_ALLOCATOR *allocator);
typedef void *(*ALLOC_ZERO_FUNC)(unsigned int size, struct MEM_ALLOCATOR *allocator);
typedef void (*FREE_FUNC)(void *ptr, struct MEM_ALLOCATOR *allocator);

typedef struct MEM_ALLOCATOR
{
	ALLOC_FUNC alloc;
	ALLOC_ZERO_FUNC alloc_zero;
	FREE_FUNC free;
	void *context;
} MEM_ALLOCATOR;

extern MEM_ALLOCATOR os_malloc_allocator;
#define dy_malloc_allocator     os_malloc_allocator

typedef struct generic_pool_struct
{
	void* pools[GENERIC_POOL_NUMBER];
	void* avail_data;
	MEM_ALLOCATOR *allocator;
	int initial_number;
	int unit_size;
	int pool_index;
	int total_number;
	int allocated_number; // This is in use
	int alloc_failure; // This is get_mem failure include malloc failure
	int flag;
	int upper_limit;
	int min_system_memory; // The system must have this number of system memory AFTER grow.
	struct
	{
		UINT16 free;
		UINT16 corrupt;
	} magic_failure;
} generic_pool_struct;

typedef struct GENERIC_LINK_DATA
{
	struct GENERIC_LINK_DATA *next;
	void * data;
} GENERIC_LINK_DATA;

typedef struct SORTED_LINKLIST_KEYINFO
{
	int	key_size;
	int	 (*key_compare)(void *keya, void *keyb);
	void (*key_assign)(void *keya, void *keyb);
	void (*key_destroy)(generic_pool_struct* pool, void *item);
	int  (*key_match)(BOOLEAN add, void *keya, void *keyb, void* param);
	void *param;
} SORTED_LINKLIST_KEYINFO;

typedef struct SORTED_LINKLIST
{
	struct SORTED_LINKLIST	*next;
	char						key; // must be in ascending order. - a variable sized key
} SORTED_LINKLIST;

typedef struct GEN_DOUBLE_LINK_LIST_ENTRY
{
	// These should always be the first two fields of your entry definition
	struct GEN_DOUBLE_LINK_LIST_ENTRY *prev;
	struct GEN_DOUBLE_LINK_LIST_ENTRY *next;
} GEN_DOUBLE_LINK_LIST_ENTRY;



typedef struct LINKLIST_TYPE
{
	struct LINKLIST_TYPE *next;
} LINKLIST_TYPE;

int init_generic_pool(generic_pool_struct *pool, int initial_number,
					  int unit_size, int flag);
void generic_free_mem_to_pool(generic_pool_struct *pool, void * item);
void* generic_get_mem_from_pool(generic_pool_struct *pool);
int init_generic_pool2(generic_pool_struct *pool, int initial_number,
					   int unit_size, int flag, MEM_ALLOCATOR *allocator);
int set_generic_pool_upper_limit(generic_pool_struct *pool, int upper_limit);
UINT32 sorted_linklist_traverse_by_reference(
	SORTED_LINKLIST_KEYINFO *key_info, UINT32 (*action)(void *, ULONG),
	SORTED_LINKLIST *dest, SORTED_LINKLIST *ref, ULONG user_para);
SORTED_LINKLIST *sorted_linklist_convert_array_to_linklist( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, UINT32 num_of_key, void *key_ary);
int sorted_linklist_is_any_present( SORTED_LINKLIST_KEYINFO *key_info, 
        SORTED_LINKLIST * A, SORTED_LINKLIST * B);
void sorted_linklist_add_from_array( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p,
	UINT32 source_ary_index, void *source_ary);
void sorted_linklist_add( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
void sorted_linklist_move( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST **src_p);
SORTED_LINKLIST* sorted_linklist_make_minus( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST* src1, SORTED_LINKLIST* src2);
void sorted_linklist_move_keep_old( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST **src_p);
SORTED_LINKLIST* sorted_linklist_make_common( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST* src1, SORTED_LINKLIST* src2);
SORTED_LINKLIST* sorted_linklist_clone( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	UINT32 (*action)(void *, void *), SORTED_LINKLIST *src);
void sorted_linklist_free_list( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST *src);
SORTED_LINKLIST* sorted_linklist_add_one_item(generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, void *src);
void sorted_linklist_minus( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
void sorted_linklist_keep_common( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
void free_generic_pool(generic_pool_struct *pool);
void generic_free_entire_linklist(GENERIC_LINK_DATA* head, generic_pool_struct *pool);
void **general_alloc_memory_chain2(generic_pool_struct *pool, int size, void * avail);
int get_pool_grow_factor(int index);
UINT32 mem_round_up_size(UINT32 size);
void quick_sort_generic_anykey(int start_index, int end_index,
						UINT32* index_ary, char* val_ary,
						SORTED_LINKLIST_KEYINFO *key_info);
SORTED_LINKLIST *sorted_linklist_alloc_and_append( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **head, SORTED_LINKLIST *prev, void *key);
void sorted_linklist_merge( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST **src_p);
SORTED_LINKLIST* sorted_linklist_del_one_item(generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, void *src);
int generic_get_pool_upper_limit(generic_pool_struct *pool);
int generic_get_pool_total_number(generic_pool_struct *pool);
int sorted_linklist_is_subset( SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST * A, SORTED_LINKLIST * B);

#endif //__L2MCD_DATA_STRUCT__
