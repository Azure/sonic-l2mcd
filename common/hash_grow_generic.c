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
/* This hash table does not use anchors. It double its size
   whenever it is half full. When it is expanding, it rehashes.

   This hash table is very generic. It can supports different kinds
   of key structure. If the key is not UINT32, you might need to provide
   hash_function, key_init and key_compare function. See the bottom random
   test program for usage.
 */


#include </usr/include/memory.h>
#include <string.h>
#include "l2mcd_data_struct.h"
#include "hash_grow_generic.h"
#include "l2mcd.h"
#define STACK_DEPTH 28
#include "wheel_timer.h"

#define SAME_KEY(key1, key2) ((key1 == key2))
#define HASH_FUNCTION(aHash, key) (((key*17) % aHash->size))

#define PRIME_ARY 21
static int prime_ary[PRIME_ARY]=
{11, 23, 37, 59, 89, 131, 197, 293, 439, 659, 983, 
 1471, 2207, 3301, 4951, 7417, 10007, 15013, 22573, 33857, 50789};

static int hash_grow_generic_dont_rehash = 0;

static int find_next_prime(int num)
{
	int i=0;
	while(i<PRIME_ARY && num>prime_ary[i])
		i++;
	if(i < PRIME_ARY)
		return prime_ary[i];
	return (num+(num>>1)); /* make 1.5 times bigger */
}


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
	int (*key_compare)(unsigned long , unsigned long ), /* comparing the key. Use internal compare if NULL */
	UINT32 (*hash_function)(unsigned long ), /* for calculating the hash value. Use internal hash if NULL  */
	int (*key_init)(unsigned long *,unsigned long)) /* handling the key. Doesn't do anything if NULL */
{
#if 1
	return hashGrowGenericCreate2(estimated_entry_number, mode, key_compare,
		hash_function, key_init, &dy_malloc_allocator);
#endif
}

hashGrowGeneric *hashGrowGenericCreate2(int estimated_entry_number, int mode,
	int (*key_compare)(unsigned long , unsigned long ), /* comparing the key. Use internal compare if NULL */
	UINT32 (*hash_function)(unsigned long ), /* for calculating the hash value. Use internal hash if NULL  */
	int (*key_init)(unsigned long *,unsigned long), /* handling the key. Doesn't do anything if NULL */
	MEM_ALLOCATOR *allocator)
{
	hashGrowGeneric *aHash;
	int size;
	size = find_next_prime((estimated_entry_number*3)>>1);
	aHash= (hashGrowGeneric *)allocator->alloc_zero(sizeof(*aHash), allocator);
	if(!aHash)
	{
		L2MCD_LOG_ERR("%s aHash alloc fail %d ", __FUNCTION__,estimated_entry_number);
		return NULL;
	}
    aHash->allocator = allocator;
    aHash->size=size;
	aHash->mode=mode;
    aHash->key_ary=(unsigned long *)allocator->alloc(sizeof(*(aHash->key_ary))*size, allocator);
    aHash->data_ary=(unsigned long *)allocator->alloc(sizeof(*(aHash->data_ary))*size, allocator);
    aHash->flag_ary=(UINT8 *)allocator->alloc_zero(sizeof(char)*size, allocator); // all should be zero
	if(!aHash->key_ary || !aHash->data_ary || !aHash->flag_ary)
	{
		if(aHash->key_ary)
			allocator->free(aHash->key_ary, allocator);
		if(aHash->data_ary)
			allocator->free(aHash->data_ary, allocator);
		if(aHash->flag_ary)
			allocator->free(aHash->flag_ary, allocator);
		allocator->free(aHash, allocator);
		return NULL;
	}
	aHash->key_compare = key_compare;
	aHash->hash_function = hash_function;
	aHash->key_init = key_init;
	return aHash;
}

/* This free its contents and itself. It does not free each individual data */
void hashGrowGenericDestroy(hashGrowGeneric *aHash)
{
	MEM_ALLOCATOR *allocator = aHash->allocator;
	allocator->free(aHash->key_ary, allocator);
    allocator->free(aHash->data_ary, allocator);
    allocator->free(aHash->flag_ary, allocator);
	if(aHash->sorted_ary)
		allocator->free(aHash->sorted_ary, allocator);
	allocator->free(aHash, allocator);
}

/* This frees its contents and itself. It calls free_func(key,data) for each individual data*/
void hashGrowGenericDestroyAndFreeContents(hashGrowGeneric *aHash, 
				void (*free_func)(unsigned long, unsigned long))
{
	int i;
	UINT8 *flag_ary = aHash->flag_ary;
	hash_grow_generic_dont_rehash = 1;
	if(aHash->index)
	{
		for(i=aHash->size-1; i>=0; i--)
		{
			if(flag_ary[i]==1 )
			{
				free_func(aHash->key_ary[i], aHash->data_ary[i]);
			}
		}
	}
	hashGrowGenericDestroy(aHash);
	hash_grow_generic_dont_rehash = 0;
}

/* return the number of hash entries including empty ones */
int hashGrowGenericGetTableSize(hashGrowGeneric *aHash)
{
	return aHash->size;
}

/* return the number of hash entries excluding empty ones */
int hashGrowGenericGetTableEntries(hashGrowGeneric *aHash)
{
	return aHash->index;
}

/* Suppose the hash table is never full */
static int find_a_space(hashGrowGeneric *aHash, unsigned long key)
{
    UINT32 hash_val;
	if(!aHash->hash_function)
		hash_val=HASH_FUNCTION(aHash, key);
	else
		hash_val = aHash->hash_function(key)%aHash->size;
    while(aHash->flag_ary[hash_val]==1)
	{ 
		hash_val=(hash_val+1)%aHash->size;
    }
    return hash_val;
}

/* return -1: not available, else OK */
static int find_an_item(hashGrowGeneric *aHash, unsigned long key)
{
	char * flag_ary = (char *)aHash->flag_ary;
	UINT32 hash_val, start_hash_val;
	
	if(aHash->hash_function)
		hash_val = aHash->hash_function(key)%aHash->size;
	else
		hash_val=HASH_FUNCTION(aHash, key);

	start_hash_val = hash_val;
	while(flag_ary[hash_val])
	{ 
		if(flag_ary[hash_val]==1)
		{
			if(!aHash->key_compare)
			{
				if(SAME_KEY(key, aHash->key_ary[hash_val]))
					return hash_val;
			}
			else 
			{
				if(!aHash->key_compare(key, aHash->key_ary[hash_val]))
					return hash_val;
			}
		}
		hash_val=(hash_val+1)%aHash->size;
		if (hash_val == start_hash_val)
			break;
	}
	return -1; // fail to find it
}

static int hashGrowGenericRehash(hashGrowGeneric *aHash, int newsize)
{
	int i;
    unsigned long *oldkey_ary=aHash->key_ary;
    unsigned long *olddata_ary=aHash->data_ary;
    UINT8 *oldflag_ary=aHash->flag_ary; //0: EMPTY, 1: FULL, 2: DELETED
    int oldindex=aHash->index;
	int oldsize = aHash->size;
	MEM_ALLOCATOR *allocator = aHash->allocator;

    aHash->index=0;
    aHash->size = newsize; //get the next size 
    aHash->key_ary=(unsigned long *)allocator->alloc(sizeof(*(aHash->key_ary))*newsize, allocator);
    aHash->data_ary=(unsigned long *)allocator->alloc(sizeof(*(aHash->data_ary))*newsize, allocator);
    aHash->flag_ary=(UINT8 *)allocator->alloc_zero(sizeof(char)*newsize, allocator); // all should be zero
	if(!aHash->key_ary || !aHash->data_ary || !aHash->flag_ary)
	{
		if(aHash->key_ary)
			allocator->free(aHash->key_ary, allocator);
		aHash->key_ary = oldkey_ary;
		if(aHash->data_ary)
			allocator->free(aHash->data_ary, allocator);
		aHash->data_ary = olddata_ary;
		if(aHash->flag_ary)
			allocator->free(aHash->flag_ary, allocator);
		aHash->flag_ary = oldflag_ary;
		aHash->size = oldsize;
		aHash->index = oldindex;
		return 0;
	}

    for(i=0; i<oldsize; i++)
	{ // rehash the table 
		if(oldflag_ary[i]==1)
		{ // full
			int ind;
			ind=find_a_space(aHash, oldkey_ary[i]); //find a space
			aHash->key_ary[ind]=oldkey_ary[i];
			aHash->data_ary[ind]=olddata_ary[i];
			aHash->flag_ary[ind]=1;
		}
    }
	aHash->index = oldindex;
    allocator->free(oldkey_ary, allocator);
    allocator->free(olddata_ary, allocator);
    allocator->free(oldflag_ary, allocator);
	aHash->del_cnt = 0;
    return 1;
}

/* return 0: out of memory, 1: success, 
   2: duplicated key and data is overwritten */
int hashGrowGenericInsert(hashGrowGeneric *aHash, unsigned long key, unsigned long data)
{
    int ind;

	if(aHash->index>(aHash->size*2/3))
	{	/* 66% full */
		if(aHash->mode & HASH_GROW_DO_NOT_GROW)
			return 0; /* Cannot grow, out of space */
		if(!hashGrowGenericRehash(aHash, (aHash->size *2 -1)))
		{
			return 0;
		}
	}

    ind=find_an_item(aHash,key); /* find this item */
    if(ind>=0) // duplicated */
	{ 
		aHash->data_ary[ind]=data;
		return 2;
    }
	ind=find_a_space(aHash, key); //find a space
	if(ind<0)
		return 0;
	if(aHash->key_init)
	{
		if(!(aHash->key_init(&aHash->key_ary[ind], key))) // out of memory
			return 0;
	}
	else 
		aHash->key_ary[ind]=key;
    aHash->data_ary[ind]=data;
    aHash->flag_ary[ind]=1;
    aHash->index++;
    return 1; 
}

void delete_sorted_array(hashGrowGeneric* aHash)
{
	if(aHash->sorted_ary)
	{
		MEM_ALLOCATOR *allocator = aHash->allocator;
		allocator->free(aHash->sorted_ary, allocator);
		aHash->sorted_ary = NULL;
	}
}

static void delete_entry(hashGrowGeneric* aHash, int i)
{
	aHash->flag_ary[i]=2; //deleted
	aHash->index--;
	aHash->del_cnt ++;
	if(aHash->del_cnt >= (aHash->size>>3))
	{	// more than 1/8 deletion, should rehash */
		int size;
		if(!(aHash->mode & HASH_GROW_DO_NOT_SHRINK) && 
			(aHash->index < (aHash->size >>2)))
		{	/* It is less than 1/4 full, shrink to smaller size */
			size = find_next_prime(aHash->index *2);
		}
		else 
			size = aHash->size;

		if(!hash_grow_generic_dont_rehash)
			hashGrowGenericRehash(aHash, size);
	}

	delete_sorted_array(aHash);
}

/* delete the entry with a particular key. return 1 if found.
   The ret_key return the internal key so you can free its memory if necessary.
   You can provide a NULL pointer if you don't care.
   This function could cause rehash and takes a lot of time */
int hashGrowGenericDelete(hashGrowGeneric *aHash, unsigned long key, unsigned long *ret_key)
{
	int i;
    i=find_an_item(aHash, key);
    if(i>=0) 
	{ // got it
		if(ret_key)
			*ret_key = aHash->key_ary[i];
		delete_entry(aHash, i);
		return 1;
    }
    return 0; //fail in getting it 
}

/* return 1 and put result into *data if success, otherwise return 0 */
int hashGrowGenericGet(hashGrowGeneric* aHash, unsigned long key, unsigned long *data)
{
	int i;
	if(!aHash)
		return 0;
    i=find_an_item(aHash,key);
    if(i>=0) 
	{ // got it
		*data=aHash->data_ary[i];
		return 1;
    }
    return 0; //fail in getting it 
}

/* return index and put result into *data if success, otherwise return -1 */
int hashGrowGenericGetReturnIndex(hashGrowGeneric* aHash, unsigned long key, unsigned long *data)
{
	int i;
    i=find_an_item(aHash,key);
    if(i>=0) 
	{ // got it
		*data=aHash->data_ary[i];
		return i;
    }
    return -1; //fail in getting it 
}

/* If success, put result into *data before deleting this entry, and return 1*/
/*   The ret_key return the internal key so you can free its memory if necessary.
   You can provide a NULL pointer if you don't care. */
int hashGrowGenericGetAndDelete(hashGrowGeneric* aHash, unsigned long key, 
			unsigned long *data, unsigned long *ret_key)
{
	int i;
    i=find_an_item(aHash,key);
    if(i>=0) 
	{ // got it
		if(ret_key)
			*ret_key = aHash->key_ary[i];
		*data=aHash->data_ary[i];
		delete_entry(aHash, i);
		return 1;
    }
    return 0; //fail in getting it 
}

/* return 1 if found it, else 0 */
int hashGrowGenericGetSmallestKey(hashGrowGeneric* aHash, unsigned long *key, unsigned long *data)
{
	int i,ind=-1;
	UINT32 min=0; // init to avoid compiling warning
	unsigned long *key_ary;
	UINT8 *flag_ary;
	if(!aHash || aHash->index==0)
		return 0;
	key_ary = aHash->key_ary;
	flag_ary = aHash->flag_ary;
	if(!aHash->key_compare)
	{
		min=0xffffffff;
		for(i=aHash->size-1; i>=0; i--)
		{
			if(flag_ary[i] ==1)
			{
				if(key_ary[i]<min)
				{
					min = key_ary[i];
					ind = i;
				}
			}
		}
	}
	else
	{
		for(i=aHash->size-1; i>=0; i--)
		{
			if(flag_ary[i] ==1)
			{
				if(ind<0 || aHash->key_compare(key_ary[i],min) <0)
				{
					min = key_ary[i];
					ind = i;
				}
			}
		}
	}

	if(ind>=0)
	{
		*key = key_ary[ind];
		*data = aHash->data_ary[ind];
		return 1;
	}
	return 0;
}

/* get the data with the smallest *key > small_key,
   return 1 if found it, else 0 */
int hashGrowGenericGetNextKey(hashGrowGeneric* aHash, unsigned long small_key, 
					   unsigned long *key, unsigned long *data)
{
	int i,ind=-1;
	unsigned long min=0; // init to avoid compiling warning
	UINT8 *flag_ary;
	unsigned long* key_ary;
	if(!aHash || aHash->index==0)
		return 0;
	flag_ary = aHash->flag_ary;
	key_ary = aHash->key_ary;
	if(!aHash->key_compare)
	{
		min = (unsigned long)-1;
		for(i=aHash->size-1; i>=0; i--)
		{
			if(flag_ary[i] ==1)
			{
				if((key_ary[i] < min) &&(key_ary[i] > small_key))
				{
					min = key_ary[i];
					ind = i;
				}
			}
		}
	}
	else
	{
		for(i=aHash->size-1; i>=0; i--)
		{
			if(flag_ary[i] ==1)
			{
				if((ind<0 && aHash->key_compare(key_ary[i], small_key)>0) ||
					(ind>=0 && (aHash->key_compare(key_ary[i], min) <0) && 
					 (aHash->key_compare(key_ary[i], small_key) >0)))
				{
					min = key_ary[i];
					ind = i;
				}
			}
		}
	}

	if(ind>=0)
	{
		*key = key_ary[ind];
		*data = aHash->data_ary[ind];
		return 1;
	}
	return 0;
}

// sort it from small to big
static int partition(int p, int r, UINT32 *ind_ary, unsigned long *val_ary,
                            int compare_func(unsigned long, unsigned long))
{
    UINT32 x;
    x=val_ary[ind_ary[(p+r)>>1]];
    while(1)
    {
        //      while(val_ary[ind_ary[r]]>x)
        while(compare_func(val_ary[ind_ary[r]], x) > 0)
            r--;
        //      while(val_ary[ind_ary[p]]<x)
        while(compare_func(val_ary[ind_ary[p]], x) < 0)
            p++;
        if(p < r)
        {
            UINT32 temp=ind_ary[p];
            ind_ary[p]=ind_ary[r];
            ind_ary[r]=temp;
            p++;
            r--;
        }
        else
            return r;
    }
}

// *** NOTE ***: end_index is inclusive. (from start_index up to end_index).
// sort all items between [start_index, end_index] inclusive.
// It rearranage index_ary[], so that
// compare_func(val_ary[index_ary[i]], val_ary[index_ary[j]])< 0 for i < j.
// val_ary[] is unchanged.
// compare_func(x,y) should return -1, 0, or +1 if x<y, x==y and x>y, respectively
// This is a non-recursive function. The program is arranaged so that the stack[]
// usage is 2*log N in the worst case. Here, N is total number. Even N is 1,000,000,
// log N is only 20. Thus this function is safe.
void quick_sort_generic(int start_index, int end_index,
                                UINT32* index_ary, unsigned long* val_ary,
                                                        int compare_func(unsigned long, unsigned long))
{
    int stack[STACK_DEPTH*2], index=2;
    while(index != 0)
    {
        if(start_index < end_index)
        {
            int q = partition(start_index, end_index, index_ary, val_ary, compare_func);
            // put the longer one to stack and process the short one immediately.
            // This guarantees that the max depth is log N.
            if(q-start_index < end_index - q)
            {
                stack[index] = q+1;
                stack[index+1] = end_index;
                end_index = q;
            }
            else
            {
                stack[index] = start_index;
                stack[index+1] = q;
                start_index = q+1;
            }
            index+=2;
        }
        else
        {
            index-=2;
            start_index = stack[index];
            end_index = stack[index+1];
        }
    }
}

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
			UINT32 user_para1, UINT32 user_para2)
{
	UINT32 *index_ary;
	unsigned long key, data, res;
	UINT32 cnt=0, entries_processed =0;
	if(!aHash || !aHash->index || (int)skip > aHash->index)
		return 0;
	index_ary = (UINT32 *)dy_malloc(sizeof(UINT32)*aHash->index);
	if(index_ary)
	{
		UINT32 i;
		for(i=0; (int)i<aHash->size; i++)
		{
			if(aHash->flag_ary[i] ==1)
			{
				index_ary[cnt++]=i;
			}
		}
		quick_sort_generic(0, aHash->index-1, index_ary, aHash->key_ary, aHash->key_compare);
		for(i=skip; (int)i<aHash->index; i++)
		{
			UINT32 rval = action(aHash->key_ary[index_ary[i]], aHash->data_ary[index_ary[i]], i,
				user_para1, user_para2);
			entries_processed += rval & (0x7fffffff);
			if((rval & 0x80000000) | (entries_processed > item_to_process))
			{
				dy_free(index_ary);
				return entries_processed;
			}
		}
		dy_free(index_ary);
		return entries_processed;
	}
	// Cannot allocate memory, must use slow algorithm O(N^2)
	res = hashGrowGenericGetSmallestKey(aHash, &key, &data);
	while(res)
	{
		UINT32 rval;
		if(cnt >= skip)
		{
			rval = action(key, data, cnt, user_para1, user_para2);
			entries_processed += rval & (0x7fffffff);
			if(rval & 0x80000000 || entries_processed >= item_to_process)
				return entries_processed;
		}
		cnt ++;
		res = hashGrowGenericGetNextKey(aHash, key, 
				   &key, &data);
	}
	return entries_processed;
}

// sort it from small to big
static int partition_no_index2(int p, int r, unsigned long *val_ary,
                    int compare_func(unsigned long, unsigned long, unsigned long user_data),
                                unsigned long user_data)
{
    unsigned long x;
    x=val_ary[(p+r)>>1];
    while(1)
    {
        //      while(val_ary[ind_ary[r]]>x)
        while(compare_func(val_ary[r], x, user_data) >0)
            r--;
        //      while(val_ary[ind_ary[p]]<x)
        while(compare_func(val_ary[p], x, user_data) <0)
            p++;
        if(p < r)
        {
            unsigned long temp=val_ary[p];
            val_ary[p]=val_ary[r];
            val_ary[r]=temp;
            p++;
            r--;
        }
        else
            return r;
    }
}

// *** NOTE ***: end_index is inclusive. (from start_index up to end_index).
// sort all items between [start_index, end_index] inclusive.
// It rearranage val_ary[], so that
// compare_func(val_ary[i], val_ary[j])< 0 for i < j.
// compare_func(x,y) should return -1, 0, or +1 if x<y, x==y and x>y, respectively
// This is a non-recursive function. The program is arranaged so that the stack[]
// usage is 2*log N in the worst case. Here, N is total number. Even N is 1,000,000,
// log N is only 20. Thus this function is safe.
void quick_sort_generic_no_index2(int start_index, int end_index,
                                unsigned long* val_ary,
                                                        int compare_func(unsigned long, unsigned long, unsigned long user_data),
                                                                                unsigned long user_data)
{
    int stack[STACK_DEPTH*2], index=2;
    while(index != 0)
    {
        if(start_index < end_index)
        {
            int q = partition_no_index2(start_index, end_index, val_ary, compare_func, user_data);
            // put the longer one to stack and process the short one immediately.
            // This guarantees that the max depth is log N.
            if(q-start_index < end_index - q)
            {
                stack[index] = q+1;
                stack[index+1] = end_index;
                end_index = q;
            }
            else
            {
                stack[index] = start_index;
                stack[index+1] = q;
                start_index = q+1;
            }
            index+=2;
        }
        else
        {
            index-=2;
            start_index = stack[index];
            end_index = stack[index+1];
        }
    }
}

void quick_sort_generic_no_index(int start_index, int end_index,
                                unsigned long * val_ary,
                                                        int compare_func(unsigned long, unsigned long))
{
    /* HACK ALERT: Note that here we are casting the callback function
     * pointer into one with one more parameter.  This may not be
     * completely portable, but seems to be the simplest and most
     * efficient way to provide the support for both types of callback
     * functions. - mlavine
     */
    quick_sort_generic_no_index2(start_index, end_index, val_ary,
            (int (*)(unsigned long, unsigned long, unsigned long)) compare_func, 0);
}

/* The following string_key_compare(), string_key_hash_function(), and
   string_key_init() are defined here for user's convenience. If a user
   has a different type of key data structure other than string or UINT32,
   they must write their own callback functions. */
int string_key_compare(unsigned long key1, unsigned long key2)
{
	return strcmp((char*)key1,(char*)key2);
}

UINT32 string_key_hash_function(unsigned long key)
{	// key is really string pointer
	UINT32 value=0;
	UINT8 *str = (UINT8*)key;
	while(*str)
	{
		value += *str;
		value*=97;
		str++;
	}
	return value;
}

int string_key_init(unsigned long* internal_key,unsigned long your_key) /* handling the key. Doesn't do anything if NULL */
{
	int len=strlen((char*)your_key);
	if(!(*internal_key = (unsigned long) dy_malloc(len+1)))
		return 0;
	strcpy((char*)(*internal_key), (char*)your_key);
	return 1;
}
