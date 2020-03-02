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

#ifndef _HASH_GROW_GENERIC_H_
#define _HASH_GROW_GENERIC_H_

/* This hash table does not use anchors. It double its size
   whenever it is half full. When it is expanding, it rehashes.

   This hash table is very generic. It can supports different kinds
   of key structure. If the key is not UINT32, you might need to provide
   hash_function, key_init and key_compare function. See the bottom random
   test program in .c file for usage.
 */

#ifndef _ALLOCATOR_H_
#include "l2mcd_data_struct.h"
#endif

typedef struct generic_linklist
{
	struct generic_linklist *next;
}generic_linklist;



#define HASH_GROW_DO_NOT_GROW 1
#define HASH_GROW_DO_NOT_SHRINK 2
#define HASH_GROW_DO_NOT_REHASH 4
typedef struct hashGrowGeneric
{ // the key is of integer type
	unsigned long *key_ary;
    unsigned long *data_ary;
    UINT8 *flag_ary; // 0: EMPTY, 1: FULL, 2: DELETED
	int (*key_compare)(unsigned long, unsigned long); /* for comparing whether it is the same key */
	UINT32 (*hash_function)(unsigned long); /* for calculating the hash value */
	int (*key_init)(unsigned long *,unsigned long); /* handling the key */
	MEM_ALLOCATOR *allocator;
    int size;
    int index;
	int mode;
	int del_cnt; /* used in automatic rehasing */
	unsigned long *sorted_ary; // only used in storing sorted array.
	UINT32 sorted_ary_index;
} hashGrowGeneric;

/* create a hash table whose estimated number of entries is estimate_entry_number.
   It automatically grows. Insertion or deletion could takes much time
   if rehashing happens. So this hash table should only be used when
   the insertion and deletion is triggered by CLI commands.
   Advantage of this hash table: growable (very dynamic), fast finding.

   mode is indicated by OR of possible HASH_GROW_DO_NOT_GROW and 
   HASH_GROW_DO_NOT_SHRINK. The default is automatic grow and shrink.

   int key_compare(UINT32 key1, UINT32 key2) : return <0 if key1<key2,
			=0 if key1==key2, >0 if key1 > key2; 
   UINT32 hash_function(UINT32 key1), return a randomized large UINT32 (>1 million). 
				The returned number should be the same for the same key.
   int key_init(UINT32* internal_key_pointer, UINT32 the_key_you_pass);
       You do whatever you want such as malloc a memory to the internal_key_pointer,
	   and copy your key to the alloc structure. return 0 if malloc failure.
   If you malloc the key pointer in key_init, you need to free key pointer after you call
   hashGrowGenericDelete() or hashGrowGenericGetAndDelete(). Both function provides
   the parameter for you to get the internal key pointer back.

  Example, we are going to use the generic hash for string key. There are two choices:
  1) You keep the keys somewhere and the hash table only keeps the pointer.

  		aHash = hashGrowGenericCreate(initsize, 0, string_key_compare, 
			string_key_hash_function, NULL);
		You don't need to do anything after hashGrowGenericDelete().

  2) You don't keep the key and the hash table allocates a memory and copy
     the key.

	 aHash = hashGrowGenericCreate(initsize, 0, string_key_compare, 
			string_key_hash_function, string_key_init);

	 // You must free the internal key pointer after key deletion.

	 res1 = hashGrowGenericDelete(aHash, (UINT32)key, &ret_key);
	 or
	 res1 = hashGrowGenericGetAndDelete(aHash, (UINT32)key, &junk, &ret_key);
	 if(res1)
		dy_free((char*)ret_key);


   This file provides one example for int key, and one for string key. If your key
   is other type, you need to provides your own function of key_compare(), hash_function()
   and key_init().

*/
hashGrowGeneric *hashGrowGenericCreate(int estimated_entry_number, int mode,
	int (*key_compare)(unsigned long, unsigned long), /* comparing the key. Use internal compare if NULL */
	unsigned int (*hash_function)(unsigned long), /* for calculating the hash value. Use internal hash if NULL  */
	int (*key_init)(unsigned long *,unsigned long)); /* handling the key. Doesn't do anything if NULL */

hashGrowGeneric *hashGrowGenericCreate2(int estimated_entry_number, int mode,
	int (*key_compare)(unsigned long, unsigned long), /* comparing the key. Use internal compare if NULL */
	UINT32 (*hash_function)(unsigned long), /* for calculating the hash value. Use internal hash if NULL  */
	int (*key_init)(unsigned long *,unsigned long), /* handling the key. Doesn't do anything if NULL */
	MEM_ALLOCATOR *allocator);

/* This free its contents and itself. It does not free each individual data */
void hashGrowGenericDestroy(hashGrowGeneric *aHash);

/* This frees its contents and itself. It calls free_func(data) for each individual data*/
void hashGrowGenericDestroyAndFreeContents(hashGrowGeneric *aHash, 
				void (*free_func)(unsigned long, unsigned long));

/* return the number of hash entries including empty ones */
int hashGrowGenericGetTableSize(hashGrowGeneric *aHash);
/* return the number of hash entries excluding empty ones */
int hashGrowGenericGetTableEntries(hashGrowGeneric *aHash);

/* return 1 and put result into *data if success, otherwise return 0 */
int hashGrowGenericGet(hashGrowGeneric* aHash, unsigned long key, unsigned long *data);
/* return index and put result into *data if success, otherwise return -1 */
int hashGrowGenericGetReturnIndex(hashGrowGeneric* aHash, unsigned long key, unsigned long *data);

/* If success, put result into *data before deleting this entry, and return 1*/
/*   The ret_key return the internal key so you can free its memory if necessary.
   You can provide a NULL pointer if you don't care. */
int hashGrowGenericGetAndDelete(hashGrowGeneric* aHash, unsigned long key, 
			unsigned long *data, unsigned long *ret_key);

/* return 0: out of memory, 1: success, 
   2: duplicated key and data is overwritten */
int hashGrowGenericInsert(hashGrowGeneric *aHash, unsigned long key, unsigned long data);

/* delete the entry with a particular key. return 1 if found.
   The ret_key return the internal key so you can free its memory if necessary.
   You can provide a NULL pointer if you don't care.
   This function could cause rehash and takes a lot of time */
int hashGrowGenericDelete(hashGrowGeneric *aHash, unsigned long key, unsigned long *ret_key);


/* return 1 if found it, else 0 */
int hashGrowGenericGetSmallestKey(hashGrowGeneric* aHash, unsigned long *key, unsigned long *data);

/* get the data with the smallest *key > small_key,
   return 1 if found it, else 0 */
int hashGrowGenericGetNextKey(hashGrowGeneric* aHash, unsigned long small_key, 
					   unsigned long *key, unsigned long *data);

// This subroutine use O(N log N) algorithm to sort all entries based on key.
// Then it traverse entries in a sorted manner. Note: the hash table is unchanged.
// return the sum of callback functions.
// It no memory available, it use O(N^2) algorithm to traverse.
// skip: number of entries to skip.
// item_to_process: process until the sum of callback return.
// UINT32 action(UINT32 key, UINT32 data, UINT32 user_para1, UINT32 user_para2);
// The callback function returns #_of_processed. if the highest bit
// (0x80000000) is on, it stops the traversing.
int hashGrowGenericTraverseBySortedKey(hashGrowGeneric* aHash, 
			UINT32 (*action)(unsigned long, unsigned long, UINT32, UINT32, UINT32), 
			UINT32 skip /* items to skip */, 
			UINT32 item_to_process,
			UINT32 user_para1, UINT32 user_para2);

/* The following string_key_compare(), string_key_hash_function(), and
   string_key_init() are defined here for user's convenience. If a user
   has a different type of key data structure other than string or UINT32,
   they must write their own callback functions. */
int string_key_compare(unsigned long key1, unsigned long key2);
UINT32 string_key_hash_function(unsigned long key);
int string_key_init(unsigned long* internal_key,unsigned long your_key); /* handling the key. Doesn't do anything if NULL */
void delete_sorted_array(hashGrowGeneric* aHash);

#endif /* _HASH_GROW_H_ */





