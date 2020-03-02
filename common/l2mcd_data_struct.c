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
#include <string.h>
#include "l2mcd_data_struct.h"
#include "wheel_timer.h"


static void *os_malloc_alloc_func(unsigned int size, MEM_ALLOCATOR *allocator)
{
    return os_malloc(size);
}

static void *os_malloc_alloc_zero_func(unsigned int size, MEM_ALLOCATOR *allocator)
{
    return os_malloc_zero(size);
}

static void os_malloc_free_func(void *ptr, MEM_ALLOCATOR *allocator)
{
    os_free(ptr);
}

MEM_ALLOCATOR os_malloc_allocator = { os_malloc_alloc_func, os_malloc_alloc_zero_func, os_malloc_free_func };

// This initialize the pool. You can call it once for every pool.
// initial_number: The initial number of entries in pool.
// unit_size: the size of each entry.

// flag controls the behavior of this pool. It is the OR of the following:
// GENERIC_POOL_NO_GROW: The pool does not grow. The memory is continuous.
// GENERIC_POOL_DONT_ALLOC: No memory is allocated until the first get_from_pool()
// GENERIC_POOL_LINEAR_GROW: When out of memory, we allocate initial_number.
//    It does not exponential grow (1.5X). Please note that linear grow can
//    only allocate total up to GENERIC_POOL_NUMBER times of the initial number. The defaule
//    exponential grow can allocate total
//   ((GENERIC_POOL_NUMBER - MAX_POOL_GROW_FACTOR +1) *20 +32 ) * initial_number.
//
// The default 0: automatic grow, initially allocated memory and exponential grow.
int init_generic_pool(generic_pool_struct *pool, int initial_number,
					  int unit_size, int flag)
{
	return init_generic_pool2(pool, initial_number,
							  unit_size, flag, &dy_malloc_allocator);
}

static int partition_anykey(int p, int r, UINT32 *ind_ary, char *val_ary,
						SORTED_LINKLIST_KEYINFO *key_info)
{
	char *pivot_key = &(val_ary[ind_ary[(p+r)>>1]*key_info->key_size]);

	while(1)
	{
		while(key_info->key_compare(&(val_ary[ind_ary[r]*key_info->key_size]), pivot_key) > 0)
			r--;
		while(key_info->key_compare(&(val_ary[ind_ary[p]*key_info->key_size]), pivot_key) < 0)
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

// return an item to the pool
void generic_free_mem_to_pool(generic_pool_struct *pool, void * item)
{
	//static MSG_RATE_LIMIT msg_rl;
	
	if(!pool || !item)
		return;

	if (pool->flag & GENERIC_POOL_MEMCHK_ON)
	{
		UINT32* p_magic;
		
		p_magic = (UINT32*) ((uintptr_t)item + pool->unit_size - 4);
		if (*p_magic != GENPOOL_ALLOC_MAGIC)
		{
			if (*p_magic == GENPOOL_FREE_MAGIC)
			{
				pool->magic_failure.free++;
				return;
			}
			else
			{
				pool->magic_failure.corrupt++;
			}
		}

		*p_magic = GENPOOL_FREE_MAGIC;
	}

	*(void**)item = pool->avail_data;
	pool->avail_data = item;
	pool->allocated_number--;
}

// get an item from the pool. If not available, the pool expands.
// The content of the item is set to zero.
void* generic_get_mem_from_pool(generic_pool_struct *pool)
{
	/* Now get block of memory from the correct pool */
	UINT32 total_mem_size;
	int size;
	void *temp;
	BOOLEAN	upper_limit_reached = FALSE;
	
	if(!pool)
		return NULL;

	if (pool->upper_limit && (pool->allocated_number >= pool->upper_limit))
		return NULL;

	if (pool->avail_data == NULL)
	{
		if(pool->pool_index && // If it is not allocated at all, we must allocate
			((pool->flag & GENERIC_POOL_NO_GROW) ||
			/* No Memory block available, need to allocate one more pool */
			(pool->pool_index >= GENERIC_POOL_NUMBER)))
		{
			pool->alloc_failure++;
			return NULL;
		}
		if((pool->flag & GENERIC_POOL_LINEAR_GROW))
			size = pool->initial_number;
		else
			size = get_pool_grow_factor(pool->pool_index) * pool->initial_number;

		if(pool->total_number + size > pool->upper_limit)
		{
			size = pool->upper_limit - pool->total_number;
			upper_limit_reached = TRUE;
		}

		//Try to allocate memory at page boundry and not more than the
		// allowed upper limit
		if (!upper_limit_reached)
		{
			total_mem_size = size * pool->unit_size;
			total_mem_size = mem_round_up_size(total_mem_size);
			size = total_mem_size /pool->unit_size;
		}

		if (size>0)
		{
			pool->avail_data = general_alloc_memory_chain2(pool, size, NULL);
			if(pool->avail_data)
			{
				pool->pools[pool->pool_index++] = pool->avail_data;
				pool->total_number += size;
			}
			else
			{
				pool->alloc_failure++;
	//			dprintf("generic_get_mem_from_pool: out of mem\n");
				return NULL;
			}
		}
		else
		{
			pool->alloc_failure++;
			return NULL;
		}
	}
	temp = pool->avail_data;
	pool->avail_data = (void*) (*(unsigned long*)temp);
	pool->allocated_number++;
	memset(temp, 0, pool->unit_size);

	// Mark block as being allocated
	if (pool->flag & GENERIC_POOL_MEMCHK_ON)
		*(UINT32*) ((uintptr_t)temp + pool->unit_size - 4) = GENPOOL_ALLOC_MAGIC;
	
	return temp;
}

int init_generic_pool2(generic_pool_struct *pool, int initial_number,
					   int unit_size, int flag, MEM_ALLOCATOR *allocator)
{	// you can call only once
	if(!pool)
		return 0;
	memset(pool, 0, sizeof(generic_pool_struct));
	pool->allocator = allocator;
	pool->unit_size = unit_size + ((flag & GENERIC_POOL_MEMCHK_ON) ? 4 : 0);
	pool->initial_number = initial_number;
	pool->flag = flag;
	pool->upper_limit = POOL_SIZE_HUGE_NUMBER; // a huge number.
	if((flag & GENERIC_POOL_DONT_ALLOC)==0)
	{
		pool->avail_data = general_alloc_memory_chain2(pool, initial_number, NULL);
		if(pool->avail_data)
		{
			pool->pools[pool->pool_index++] = pool->avail_data;
			pool->total_number += pool->initial_number;
			return 1;
		}
	}
	return 0;
}

// Optional function: set maximum number of entries this pool can allocate.
// klin, we allow to set upper_limit after init_generic_pool().
// The system-max could be parsed after the memory allocated. Thus, we set the
// upper_limit later.
// pool->flag is set to growable.
int set_generic_pool_upper_limit(generic_pool_struct *pool, int upper_limit)
{
	if(!pool)
		return 0;

	if (upper_limit == 0)
		upper_limit = POOL_SIZE_HUGE_NUMBER;

	if(pool->total_number >= upper_limit)
		;
//		upper_limit = pool->total_number;
	else
		pool->flag &= ~GENERIC_POOL_NO_GROW;
	pool->upper_limit = upper_limit;
	return 1;
}

// If the key of an link in *dest is also in *ref, then callback with this link.
// We just traverse the two sorted arrays at most once. This is a fast algorithm.
// UINT32 (*action)(UINT32 data, UINT32 para1),
// The action function returns the sum of the action. if the highest bit
// (0x80000000) is on, it stops the traversing.
// The action cannot change the ->next or ->key field.
UINT32 sorted_linklist_traverse_by_reference(
	SORTED_LINKLIST_KEYINFO *key_info, UINT32 (*action)(void *, ULONG),
	SORTED_LINKLIST *dest, SORTED_LINKLIST *ref, ULONG user_para)
{
	UINT32 entries_processed=0;
	while(dest && ref)
	{
		int cmp = key_info->key_compare(&dest->key,&ref->key);
		if(cmp == 0)
		{
			SORTED_LINKLIST *dest_next, *ref_next;
			UINT32 rval;

			// dest and/or ref may no longer be valid; so store next
			dest_next = dest->next;
			ref_next  = ref->next;

			rval = action(dest, user_para);

			entries_processed += rval & (0x7fffffff);
			if(rval & 0x80000000)
				return entries_processed;

			dest = dest_next;
			ref  = ref_next;
		}
		else if(cmp < 0)
		{
			dest = dest->next;
		}
		else
		{
			ref=ref->next;
		}
	}

	return entries_processed;
}

// The linklist is sorted in ascending order based on key.
// klin, the key_ary is in packet memory. Don't change it.
// So we use different quick_sort to avoid changing key_ary.
// We do not add duplicated items.
SORTED_LINKLIST *sorted_linklist_convert_array_to_linklist( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, UINT32 num_of_key, void *key_ary)
{

    #define STATIC_INDEX_SIZE         200



	UINT32 i;
	char *prev = NULL;
	SORTED_LINKLIST *link, *head=NULL;
	UINT32 index_ary[STATIC_INDEX_SIZE];
	// klin, we cannot change key_ary, so we use index_ary for sorted sequence.
	UINT32 *index_ary_p;

	if (num_of_key == 0)
		return NULL;

	if(num_of_key >= STATIC_INDEX_SIZE)
		index_ary_p = (UINT32 *)os_malloc(sizeof(UINT32)*(num_of_key+1));
	else	// size is small, avoid malloc to save time.
		index_ary_p = index_ary;

	if(index_ary_p == NULL)
		return NULL; // malloc failure

	for(i=0; i<num_of_key; i++)
	{
		index_ary_p[i] = i;
	}
	index_ary_p[num_of_key] = 0;
	quick_sort_generic_anykey(0, num_of_key-1, index_ary_p, key_ary,key_info);

	for(i=1; i<=num_of_key; i++)
	{
		char *key = (char *)key_ary + index_ary_p[num_of_key-i]*key_info->key_size;
		if(prev != NULL && key_info->key_compare(key,prev) == 0) // don't add duplicated item
			continue;
		link = (SORTED_LINKLIST*)generic_get_mem_from_pool(pool);
		if(!link) // out of resource, return whatever
		{	// BUG: 28314 leakage
			if(index_ary_p != index_ary)
				dy_free(index_ary_p);
			return head;
		}
		link->next = head;
		key_info->key_assign(&link->key,key); // Add in reverse order.
		prev = &link->key;
		head = link;
	}

	if(index_ary_p != index_ary)
		dy_free(index_ary_p);

	return head;
}

// Returns TRUE if B has any element that is also in A
int sorted_linklist_is_any_present( SORTED_LINKLIST_KEYINFO *key_info, 
        SORTED_LINKLIST * A, SORTED_LINKLIST * B)
{
	while(A && B)
	{
		int cmp = key_info->key_compare(&A->key,&B->key);

		if (cmp == 0)
			return TRUE;

		if (cmp < 0)
			A = A->next;
		else /* if (cmp > 0) */
			B = B->next;
	}

	return FALSE;
}

// *dest_p = *dest_p + source_ary.
void sorted_linklist_add_from_array( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p,
	UINT32 source_ary_index, void *source_ary)
{
	SORTED_LINKLIST *B;

	B = sorted_linklist_convert_array_to_linklist(
		pool, key_info, source_ary_index, source_ary);
	sorted_linklist_add(pool, key_info, dest_p, B);

	sorted_linklist_free_list(pool, key_info, B);
}

// We just traverse the two sorted arrays at most once. This is a tricky and fast algorithm.
// dest = dest + src; src is unchanged
// dest could be changed, so it is **dest_p
void sorted_linklist_add( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src)
{
	// We create a new head.
	SORTED_LINKLIST *head=NULL, *dest, *prev = NULL; // must initialize prev
	SORTED_LINKLIST *next_entry;

	dest = *dest_p;
	while(dest && src)
	{
		int cmp = key_info->key_compare(&dest->key,&src->key);
		if(cmp == 0)
		{
			if (key_info->key_match)
			{
				key_info->key_match(TRUE /* add */, &dest->key, &src->key, key_info->param);
			}

			prev = dest;
			dest = dest->next;
			src = src->next;
			continue;
		}

		if(cmp < 0)
		{	// must advance
			prev = dest;
			dest = dest->next;
			continue;
		}

		// This is the case that dest->key > src->key.
		if(prev)
			next_entry = prev->next;
		else // This is very first
			next_entry = dest;

		prev = sorted_linklist_alloc_and_append(pool, key_info, &head, prev, &src->key);
		if(prev == NULL) // out of resource.
			goto done;
		prev->next = next_entry; // This becomes insertion.

		src = src->next;
	}

	// need to copy the src leftover.
	while(src)
	{
		prev = sorted_linklist_alloc_and_append(pool, key_info, &head, prev, &src->key);
		if(prev == NULL) // out of resource.
			goto done;
		src = src->next;
	}

done:
	if(head)
		*dest_p = head;
}

// free *dest, *dest=*src, then set *src to null. If src is NULL, then just free *dest;
// So we can use this free memory.
void sorted_linklist_move( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST **src_p)
{
	sorted_linklist_free_list(pool, key_info, *dest_p);

	if(src_p==NULL)
	{
		*dest_p = NULL;
		return;
	}

	*dest_p = *src_p;
	*src_p = NULL;
}

// We just traverse the two sorted arrays at most once. This is a fast algorithm.
// out = src1 - src2, src1 and src2 are unchanged.
SORTED_LINKLIST* sorted_linklist_make_minus( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST* src1, SORTED_LINKLIST* src2)
{
	SORTED_LINKLIST *head=NULL, *prev = NULL; // must initialize prev

	while(src1 && src2)
	{
		int cmp = key_info->key_compare(&src1->key,&src2->key);
		if(cmp == 0)
		{
			src1 = src1->next;
			src2 = src2->next;
			continue;
		}
		if(cmp > 0)
		{
			src2 = src2->next;
			continue;
		}
		prev = sorted_linklist_alloc_and_append(pool, key_info, &head, prev, &src1->key);
		if(prev == NULL)
			return head;
		src1=src1->next;
	}

	// Need to handle the src1 left over.
	while(src1)
	{
		prev = sorted_linklist_alloc_and_append(pool, key_info, &head, prev, &src1->key);
		if(prev == NULL)
			return head;
		src1=src1->next;
	}

	return head;
}

// move src_p to dest_p, However, if the item in src_p is in dest_p, then we use
// src_p. The reason is to keep the old data.
void sorted_linklist_move_keep_old( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST **src_p)
{
	// dest = ((A*B) from A) + ((B-A) from B).
	sorted_linklist_keep_common(pool, key_info, dest_p, *src_p); // now dest_p is the common part.
	sorted_linklist_minus(pool, key_info, src_p, *dest_p); // remove the common part
	sorted_linklist_merge(pool, key_info, dest_p, src_p); // dest_p is set to NULL after merge.
}

// We just traverse the two sorted arrays at most once. This is a fast algorithm.
// new list = src1 * src2, src1 and src2 are unchanged.
SORTED_LINKLIST* sorted_linklist_make_common( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST* src1, SORTED_LINKLIST* src2)
{
	SORTED_LINKLIST *head=NULL, *prev = NULL; // must initialize prev
	while(src1 && src2)
	{
		int cmp = key_info->key_compare(&src1->key,&src2->key);
		if(cmp == 0)
		{
			prev = sorted_linklist_alloc_and_append(pool, key_info, &head, prev, &src1->key);
			if(prev == NULL)
				return head;
			src1 = src1->next;
			src2=src2->next;
		}
		else if(cmp < 0)
		{
			src1 = src1->next;
		}
		else
		{
			src2=src2->next;
		}
	}

	return head;
}

// This clone a linklist. We provide the callback function
// to set other fields. If no action, just set action to NULL.
// UINT32 (*action)(UINT32 new_link, UINT32 old_link),
SORTED_LINKLIST* sorted_linklist_clone( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	UINT32 (*action)(void *, void *), SORTED_LINKLIST *src)
{
	SORTED_LINKLIST * head=NULL, *prev=NULL;

	while(src)
	{
		prev = sorted_linklist_alloc_and_append(pool, key_info, &head, prev, &src->key);
		if(!prev) // out of memory, just return whatever we have.
			return head;

		if(action)
			action(prev, src);

		src = src->next;
	}

	return head;
}

void sorted_linklist_free_list( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST *src)
{
	SORTED_LINKLIST * src_next = NULL;

	while(src)
	{
		src_next = src->next;

		key_info->key_destroy(pool, src);

		src = src_next;
	}

	return;
}

SORTED_LINKLIST* sorted_linklist_add_one_item(generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, void *src)
{
	SORTED_LINKLIST *link, *dest, *prev=NULL;

	link = (SORTED_LINKLIST*)generic_get_mem_from_pool(pool);
	if(!link) // out of resource, return whatever
		return NULL;

	key_info->key_assign(&link->key,src);

	dest = *dest_p;
	while(dest)
	{
		if(key_info->key_compare(&dest->key,src) < 0)
		{
			prev = dest;
			dest = dest->next;
		}
		else
			break;
	}

	if(prev)
	{
		link->next = prev->next;
		prev->next = link;
	}
	else
	{
		link->next = *dest_p;
		*dest_p = link;
	}

	return link;
}

void sorted_linklist_minus( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src)
{
	SORTED_LINKLIST *dest, *next_entry, *prev=NULL;

	dest = *dest_p;
	while(dest && src)
	{
		int cmp = key_info->key_compare(&dest->key,&src->key);
		if(cmp == 0)
		{
			if (key_info->key_match == NULL
				|| key_info->key_match(FALSE /* ! add */, &dest->key, &src->key, key_info->param) )
			{
				// remove dest.
				next_entry = dest->next;
				if(prev==NULL)
				{
					*dest_p = next_entry;
				}
				else
					prev->next = next_entry;

				// remove this entry
				key_info->key_destroy(pool, dest);
				dest = next_entry;
				src=src->next;
				continue;
			}
			else if (key_info->key_match != NULL)
			{
				prev = dest;
				dest = dest->next;
				src  = src->next;
			}
		}

		if(cmp > 0)
		{
			src = src->next;
		}
		else
		{
			prev = dest;
			dest = dest->next;
		}
	}
}

void sorted_linklist_keep_common( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src)
{
	SORTED_LINKLIST *dest, *next_entry, *prev=NULL;

	dest = *dest_p;
	while(dest && src)
	{
		int cmp = key_info->key_compare(&dest->key,&src->key);

		if(cmp == 0)
		{	// keep this
			prev = dest;
			dest = dest->next;
			src = src->next;
			continue;
		}

		if(cmp < 0)
		{	// must remove dest.
			next_entry = dest->next;
			if(prev == NULL)
			{
				*dest_p = next_entry;
			}
			else
				prev->next = next_entry;
			// remove this entry
			key_info->key_destroy(pool, dest);
			dest = next_entry;
		}
		else
		{
			src = src->next;
		}
	}

	// must remove the leftover
	if(dest)
	{
		if(*dest_p == dest)
			*dest_p = NULL;
		else
			prev->next = NULL;

		while(dest)
		{
			next_entry = dest->next;
			key_info->key_destroy(pool, dest);
			dest = next_entry;
		}
	}
}

// NOTE: It frees the pool memory even the individual item is in use
void free_generic_pool(generic_pool_struct *pool)
{
	int i;
	MEM_ALLOCATOR *allocator;
	if(!pool)
		return;
	allocator = pool->allocator;
	for(i=0; i<pool->pool_index; i++)
	{
		if(pool->pools[i])
			(*allocator->free)(pool->pools[i], allocator);
	}
	memset(pool, 0, sizeof(generic_pool_struct));
}

void generic_free_entire_linklist(GENERIC_LINK_DATA* head,
	generic_pool_struct *pool)
{
	GENERIC_LINK_DATA* next_entry;
	if(pool==NULL)
	{
		//uprintf("Error! generic_remove_.., pool null\n");
#ifndef WIN32
		//os_dump_call_stack();
#endif
		return;
	}
	while(head)
	{
		next_entry = head->next;
		generic_free_mem_to_pool(pool, head);
		head= next_entry;
	}
}

/* The unit_size is the bytes of one data structure, size is number of data structures */
/* The memory is chained. return size or 0*/
/* avail is the leftover you want to attach to the end of the
   new sequence. */
void **general_alloc_memory_chain2(generic_pool_struct *pool, int size, void * avail)
{
	int i;
	void **p, **q;
	int unit_size;
	MEM_ALLOCATOR* allocator;

	if(!pool)
		return NULL;

	unit_size = pool->unit_size;
	allocator = pool->allocator;
	
	if((!size) || (!unit_size))
		return NULL;

	if(!(p = (void**)allocator->alloc_zero(unit_size*size, allocator)))
		return 0;
	q=p;
	for(i=size-2; i>=0; i--)
	{
		*q = (void*)((uintptr_t)q + unit_size);

		// Insert "free" magic word
		if (pool->flag & GENERIC_POOL_MEMCHK_ON)
			*(UINT32*)((uintptr_t) q + unit_size -4) = GENPOOL_FREE_MAGIC;
		
		q = *q;
	}
	*q = avail;

	if (pool->flag & GENERIC_POOL_MEMCHK_ON)
		*(UINT32*) ((uintptr_t) q + unit_size - 4) = GENPOOL_FREE_MAGIC;

	return p;
}

/* This function controls the amount memory in a pool */
int get_pool_grow_factor(int index)
{
	#define MAX_POOL_GROW_FACTOR 7
	static int pool_factor[MAX_POOL_GROW_FACTOR]={1,1,2,4,8,16,20};
	if(index<MAX_POOL_GROW_FACTOR)
		return pool_factor[index];
	else
		return pool_factor[MAX_POOL_GROW_FACTOR-1];
}

UINT32 mem_round_up_size(UINT32 size)
{

	if (size > MEM_SIZE_4M)
		size = MEM_SIZE_8M;
	else if (size > MEM_SIZE_2M)
		size = MEM_SIZE_4M;
	else if (size > MEM_SIZE_1M)
		size = MEM_SIZE_2M;
	else if (size > MEM_SIZE_512K)
		size = MEM_SIZE_1M;
	else if (size > MEM_SIZE_256K)
		size = MEM_SIZE_512K;
	else if (size > MEM_SIZE_128K)
		size = MEM_SIZE_256K;
	else if (size > MEM_SIZE_64K)
		size = MEM_SIZE_128K;
	else if (size > MEM_SIZE_32K)
		size = MEM_SIZE_64K;
	else if (size > MEM_SIZE_16K)
		size = MEM_SIZE_32K;
	else if (size > MEM_SIZE_8K)
		size = MEM_SIZE_16K;
	else if (size > MEM_SIZE_4K)
		size = MEM_SIZE_8K;
	else if (size > MEM_SIZE_2K)
		size = MEM_SIZE_4K;
	else if (size > MEM_SIZE_1K)
		size = MEM_SIZE_2K;
	else
		size = MEM_SIZE_1K;
	return size;
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
void quick_sort_generic_anykey(int start_index, int end_index,
						UINT32* index_ary, char* val_ary,
						SORTED_LINKLIST_KEYINFO *key_info)
{
	int stack[STACK_DEPTH*2], index=2;
	while(index != 0)
	{
		if(start_index < end_index)
		{
			int q = partition_anykey(start_index, end_index, index_ary, val_ary, key_info);
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

// This is used internally. It allocate an entry and append to "prev".
// If the *head is NULL, then it is the first item, and set *head.
SORTED_LINKLIST *sorted_linklist_alloc_and_append( generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **head, SORTED_LINKLIST *prev, void *key)
{
	SORTED_LINKLIST *link;
	link = (SORTED_LINKLIST*)generic_get_mem_from_pool(pool);
	if(link)
	{
		key_info->key_assign(&link->key, key);
		if(prev==NULL)
			*head = link; // The first one.
		else
			prev->next = link; // add to the end.
	}
	return link;
}

// We just traverse the two sorted arrays at most once. This is a tricky and fast algorithm.
// dest = dest + src; src is gone into dest, and then set to NULL.
// dest could be changed, so it is **dest_p
void sorted_linklist_merge( generic_pool_struct *pool, SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST **dest_p, SORTED_LINKLIST **src_p)
{
	// We create a new head.
	SORTED_LINKLIST *head=NULL, *dest, *prev = NULL, *src, *src_next; // must initialize prev
	SORTED_LINKLIST *next_entry;

	dest = *dest_p;
	src = *src_p;
	while(dest && src)
	{
		int cmp = key_info->key_compare(&dest->key,&src->key);
		if(cmp < 0)
		{	// must advance
			prev = dest;
			dest = dest->next;
			continue;
		}

		// This is the case that dest->key > src->key.
		if(prev)
			next_entry = prev->next;
		else // This is very first
			next_entry = dest;

		src_next = src->next;

		if(prev==NULL)
			head = src; // The first one.
		else
			prev->next = src; // add to the end.

		prev = src;
		prev->next = next_entry; // This becomes insertion.

		src = src_next;
	}
	// need to append the src leftover.

	if(src)
	{
		if(prev==NULL)
			head = src; // The first one.
		else
			prev->next = src; // add to the end.
	}

	if(head)
		*dest_p = head;

	*src_p = NULL;
}

SORTED_LINKLIST* sorted_linklist_del_one_item(generic_pool_struct *pool,
	SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, void *src)
{
	SORTED_LINKLIST *next, *dest, *prev;
	int cmp;

	prev = next = NULL;

	dest = *dest_p;
	while(dest)
	{
		cmp = key_info->key_compare(&dest->key,src);

		if (cmp == 0)
		{
			next = dest->next;
			if(prev)
			{
				prev->next = next;
			}
			else
			{
				*dest_p = next;
			}

			key_info->key_destroy(pool, dest);
			return next;
		}
		else if (cmp < 0)
		{
			prev = dest;
			dest = dest->next;
		}
		else
		{
			break;
		}
	}

	return next;
}

// Returns -1 if there is no limit, else the limit
int generic_get_pool_upper_limit(generic_pool_struct *pool)
{
	if(!pool)
		return 0;

	return ((pool->upper_limit == POOL_SIZE_HUGE_NUMBER) ? -1 : pool->upper_limit);
}

// Returns total blocks allocated
int generic_get_pool_total_number(generic_pool_struct *pool)
{
	return pool ? pool->total_number : -1;
}

// Returns TRUE if B is a subset of A
int sorted_linklist_is_subset( SORTED_LINKLIST_KEYINFO *key_info,
	SORTED_LINKLIST * A, SORTED_LINKLIST * B)
{
	while(A && B)
	{
		int cmp = key_info->key_compare(&A->key,&B->key);

		if (cmp > 0)
			return FALSE;

		if (cmp <= 0)
			A = A->next;

		if (cmp == 0)
			B = B->next;
	}

	return (B == NULL);
}



