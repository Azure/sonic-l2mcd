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
#ifndef _WHEEL_TIMER_H_
#define _WHEEL_TIMER_H_


#define WHEEL_TIMER_MAGIC_NUMBER  0xF1D0D1D0
#define WHEEL_TIMER_TRAGIC_NUMBER 0xDEADBEEF

typedef unsigned long WheelTimerId;
typedef UINT32 WheelTimerSlots;
typedef UINT32 WheelTimerTics;
typedef UINT32 WheelTimerMagic;

typedef enum
{
  WheelTimerSuccess = 0,
  WheelTimerFailure = 1,
  WheelTimerBadArgument = 2,
  WheelTimerOutOfBudget = 3,
  WheelTimerOutOfMemory = 4,
} WheelTimerResult;

typedef enum
{
  WheelTimer1DLinkedList,
  WheelTimer2DLinkedList,
  WheelTimerMaxBucketTypes
} WheelTimerBucketType;

typedef struct WheelTimerLink
{
	struct WheelTimerLink *prevP;
	struct WheelTimerLink *nextP;
} WheelTimerLink;

// MUST be UINT32
typedef struct WheelTimerFlagsOptions
{
	UINT16	bucket_print:1;	// Print Bucket Node Info
	UINT16	element_print:1;	// Print Element Node Info
	UINT16	verbose:1;		// Verbose format of requested printouts (incl apps)
	UINT16	spare:12;
	UINT16	app_flags;		// opaque to wheeltimer - app dependent
} WheelTimerFlagsOptions;

typedef union WheelTimerPrintFlags
{
	WheelTimerFlagsOptions flags_options;
	UINT32	all_flags;
} WheelTimerPrintFlags;

typedef struct WheelTimerCounters
{
	UINT32	bucket_nodes;
	UINT32	elem_nodes;
} WheelTimerCounters;

typedef WheelTimerLink WheelTimerBucket;

typedef void (*WheelTimerPrintCallback)(WheelTimerPrintFlags, void*, void *);
typedef void (*WheelTimerCallback)(void*);
typedef void (*WheelTimerBucketInitFn)(void);
typedef void (*WheelTimerBucketDoneFn)(void);
typedef void (*WheelTimerBucketPrintFn)(WheelTimerBucket*, WheelTimerPrintFlags, WheelTimerCounters*, void *);

typedef struct WheelTimerElement
{
	WheelTimerLink	link;
	void            *data;
	WheelTimerCallback timeout_callback;
	WheelTimerPrintCallback printout_callback;
	WheelTimerTics  target_time;
	WheelTimerMagic	magic_num;
} WheelTimerElement;

typedef WheelTimerResult (*WheelTimerBucketInsertFn)(WheelTimerBucket*, WheelTimerElement*);
typedef WheelTimerResult (*WheelTimerBucketRemoveFn)(WheelTimerBucket*, WheelTimerElement*);
typedef WheelTimerResult (*WheelTimerBucketGetReadyItemsFn)(WheelTimerBucket*, WheelTimerTics, WheelTimerLink*);

typedef struct WheelTimerBucketPlugin
{
	WheelTimerBucketInitFn initFn; /* Optional */
	WheelTimerBucketDoneFn doneFn; /* Optional */
	WheelTimerBucketPrintFn printFn; /* Optional */

	WheelTimerBucketInsertFn insertFn; /* Required */
	WheelTimerBucketRemoveFn removeFn; /* Required*/
	WheelTimerBucketGetReadyItemsFn getReadyItemsFn; /*Required */
}WheelTimerBucketPlugin;

typedef struct WheelTimer
{
	WheelTimerBucketPlugin   bucket_plugin;
	WheelTimerCallback       timeout_callback;
	WheelTimerPrintCallback printout_callback;
	WheelTimerSlots          num_slots;
	WheelTimerSlots          cur_slot;
	WheelTimerTics           cur_time;
	WheelTimerLink           ready_queue;
	WheelTimerBucket         cir_array[1]; /* Must be the last element */
} WheelTimer;

typedef struct WheelTimerMemory
{
	WheelTimerLink	   link;
	WheelTimerMagic	   magic_num;
	WheelTimer		   timer;
} WheelTimerMemory;

#define WheelTimerMemory__Allocate(a) ((WheelTimerMemory*)dy_malloc_zero(sizeof(WheelTimerMemory)+(a-1)*sizeof(WheelTimerBucket)))
#define WheelTimerMemory__Free(a)     (dy_free((void*)a))
#define WheelTimer__GetMemoryFromTimer(a) ((WheelTimerMemory*)(((unsigned long)a)-((unsigned long)&(((WheelTimerMemory*)NULL)->timer))))
#define WheelTimer__GetMemoryFromTimerId(a) WheelTimer__GetMemoryFromTimer(a)

typedef struct WheelTimer2DNode
{
	WheelTimerLink	h_link;
	WheelTimerLink	v_link;
	WheelTimerTics  target_time;
} WheelTimer2DNode;

#define WheelTimer2DNode__Allocate() ((WheelTimer2DNode*)generic_get_mem_from_pool(wtb_2DNode_pool))
#define WheelTimer2DNode__Free(a)    (generic_free_mem_to_pool(wtb_2DNode_pool, (a)))
#define WheelTimer2DNode__GetNodeFromVLink(a) ((WheelTimer2DNode*)(((unsigned long)a)-((unsigned long)&(((WheelTimer2DNode*)NULL)->v_link))))

/* APIs into the Wheel Timer Library */

WheelTimerId WheelTimer_Create(UINT32 size, WheelTimerCallback timeout, WheelTimerPrintCallback printout, WheelTimerBucketType bucket_type);
WheelTimerResult WheelTimer_AddElement(WheelTimerId id, WheelTimerElement *elementP, WheelTimerTics offset);
WheelTimerResult WheelTimer_AddElementCallback(WheelTimerId id, WheelTimerElement *elementP, WheelTimerTics offset, WheelTimerCallback timeout_callback,
							           WheelTimerPrintCallback printout);
WheelTimerResult WheelTimer_DelElement(WheelTimerId id, WheelTimerElement *elementP);
WheelTimerResult WheelTimer_ReTimeElement(WheelTimerId id, WheelTimerElement *elementP, WheelTimerTics offset);
WheelTimerResult WheelTimer_UpdateTic(WheelTimerId id, UINT32 budget, WheelTimerTics tics);
WheelTimerResult WheelTimer_Destroy(WheelTimerId id);
WheelTimerResult WheelTimer_IsElementEnqueued(WheelTimerElement *elementP);
WheelTimerResult WheelTimer_GetTimeToExpire(WheelTimerId id, WheelTimerElement *elementP, WheelTimerTics *time);

void *os_malloc_zero(unsigned int size);
void os_free(void *ptr);
void *dy_malloc_zero(unsigned int size);
void *dy_malloc(unsigned int size);
void dy_free(void *ptr);
void *os_malloc(unsigned int size);

#endif /*_WHEEL_TIMER_H_*/
