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
#include "string.h"
#include "l2mcd_data_struct.h"
#include "wheel_timer.h"

WheelTimerLink WheelTimersHead;

static void WheelTimerLink_Link(WheelTimerLink *headP, WheelTimerLink *tailP, WheelTimerLink *nextP)
{
  headP->prevP = nextP->prevP;
  nextP->prevP->nextP = headP;
  nextP->prevP = tailP;
  tailP->nextP = nextP;
}

static void WheelTimerLink_Unlink(WheelTimerLink *headP, WheelTimerLink *tailP)
{
  headP->prevP->nextP = tailP->nextP;
  tailP->nextP->prevP = headP->prevP;
  headP->prevP = NULL;
  tailP->nextP = NULL;
}

static WheelTimer* WheelTimer__GetTimerFromId(WheelTimerId id)
{
  if (id)
  {
    WheelTimerMemory *memP = WheelTimer__GetMemoryFromTimerId(id);
    if (memP && memP->magic_num == WHEEL_TIMER_MAGIC_NUMBER)
      return &memP->timer;
  }

  return NULL;
}

static WheelTimer *WheelTimer_Allocate(UINT32 size)
{
  WheelTimerMemory *mem = WheelTimerMemory__Allocate(size);

  if (mem)
  {
    WheelTimerLink_Link(&mem->link, &mem->link, &WheelTimersHead);
    mem->magic_num = WHEEL_TIMER_MAGIC_NUMBER;
    mem->timer.ready_queue.nextP = mem->timer.ready_queue.prevP = &mem->timer.ready_queue;
    while (size-- != 0)
      mem->timer.cir_array[size].nextP = mem->timer.cir_array[size].prevP = &mem->timer.cir_array[size];
    return &mem->timer;
  }

  return NULL;
}

static void WheelTimer_Free(WheelTimer *timerP)
{
  WheelTimerMemory *memP = WheelTimer__GetMemoryFromTimer(timerP);

  if (memP)
  {
    if (memP->magic_num == WHEEL_TIMER_MAGIC_NUMBER)
    {
      memP->magic_num  = WHEEL_TIMER_TRAGIC_NUMBER;
      WheelTimerLink_Unlink(&memP->link, &memP->link);
      WheelTimerMemory__Free(memP);
    }
  }
}

static void WheelTimerElement_Print(WheelTimerElement *elementP, WheelTimerPrintFlags flags, WheelTimerCounters *counters, void *param)
{
  counters->elem_nodes++;
  if (elementP->printout_callback)
    (*elementP->printout_callback)(flags, elementP->data, param);
}

static void WheelTimerBucket_Print1DList(WheelTimerBucket* bucketP,
                                       WheelTimerPrintFlags flags,
                                       WheelTimerCounters *counters,
                                       void *param)
{
  WheelTimerLink *nextP;

  /* Walk the list and print each element */
  for (nextP = bucketP->nextP; nextP != bucketP; nextP = nextP->nextP)
  {
    WheelTimerElement_Print((WheelTimerElement*)nextP, flags, counters, param);
  }
}

static WheelTimerResult WheelTimerBucket_InsertTo1DList(WheelTimerBucket* bucketP,
                                                      WheelTimerElement *elementP)
{
  WheelTimerLink *nextP;

  /* Lets find the right place to insert, in the order of target_time */
  for (nextP = bucketP; nextP->prevP != bucketP; nextP = nextP->prevP)
  {
    WheelTimerElement *thisP = (WheelTimerElement*)nextP->prevP;
    /* Skip the ones with bigger target time (going backwards) */
    if (thisP->target_time <= elementP->target_time)
      break;
  }

  /* insert here */
  WheelTimerLink_Link(&elementP->link, &elementP->link, nextP);
  return WheelTimerSuccess;
}

static WheelTimerResult WheelTimerBucket_RemoveFrom1DList(WheelTimerBucket* bucketP,
                                                        WheelTimerElement *elementP)
{
  /* Just remove it from the list */
  WheelTimerLink_Unlink(&elementP->link, &elementP->link);
  return WheelTimerSuccess;
}

static WheelTimerResult WheelTimerBucket_GetReadyItemsFrom1DList(WheelTimerBucket *bucketP,
                                                               WheelTimerTics time,
                                                               WheelTimerLink *readyP)
{
  WheelTimerElement *elementP;

  /* If bucket is not emty */
  if (bucketP->nextP != bucketP)
  {
    /* Get the first element */
    elementP = (WheelTimerElement*)bucketP->nextP;

    /* If the element is ready */
    if (elementP->target_time <= time)
    {
      WheelTimerLink *headP, *tailP, *linkP;

      /* Get all the subsequent elements which are also ready */
      for (linkP = headP = bucketP->nextP; (tailP = linkP)->nextP != bucketP; linkP = linkP->nextP)
      {
        elementP = (WheelTimerElement*)linkP->nextP;
        if (elementP->target_time > time)
          break;
      }

      /* Unlink the list from the bucket */
      WheelTimerLink_Unlink(headP, tailP);

      /* Link it to the ready list */
      WheelTimerLink_Link(headP, tailP, readyP);
    }
  }

  return WheelTimerSuccess;
}

/* Pool of cache entries to optimise memory management */
generic_pool_struct *wtb_2DNode_pool;
UINT32 WTB_2DListPoolUsageCount;

static void WheelTimerBucket_Initialize2DList(void)
{
  if (WTB_2DListPoolUsageCount++ == 0)
  {
    int res;

    /* Initialize pool memory */
    wtb_2DNode_pool = (generic_pool_struct*)dy_malloc_zero(sizeof(generic_pool_struct));
    /* init_generic_pool() check NULL pointer. So we don't need to check here*/
    /* GENERIC_POOL_NO_GROW is reset when set_generic_pool_upper_limit()*/
    res = init_generic_pool(wtb_2DNode_pool, 100, sizeof(WheelTimer2DNode), GENERIC_POOL_NO_GROW);

    if(!res)
      return;

    set_generic_pool_upper_limit(wtb_2DNode_pool, 32000);
    return;
  }
}

static void WheelTimerBucket_CleanUp2DList(void)
{
  if (--WTB_2DListPoolUsageCount == 0)
  {
    /* Free up pool memory */
    free_generic_pool(wtb_2DNode_pool);
    dy_free(wtb_2DNode_pool);
    wtb_2DNode_pool = NULL;
  }
}

static void WheelTimerBucket_Print2DList(WheelTimerBucket* bucketP,
                                       WheelTimerPrintFlags flags,
                                       WheelTimerCounters *counters,
                                       void *param)
{
  WheelTimerLink *nextP;

  for (nextP = bucketP->nextP; nextP != bucketP; nextP = nextP->nextP)
  {
    WheelTimer2DNode *nodeP = (WheelTimer2DNode*)nextP;
    WheelTimerLink *strt1P  = &nodeP->v_link;
    WheelTimerLink *next1P;

    counters->bucket_nodes++;

    for (next1P = strt1P->nextP; next1P != strt1P; next1P = next1P->nextP)
    {
      WheelTimerElement_Print((WheelTimerElement*)next1P, flags, counters, param);
    }
  }
}

static WheelTimerResult WheelTimer2DNode_Delete(WheelTimer2DNode *nodeP)
{
  /* Unlink the column head node from the row */
  WheelTimerLink_Unlink(&nodeP->h_link, &nodeP->h_link);
  /* Destroy the node */
  WheelTimer2DNode__Free(nodeP);
  return WheelTimerSuccess;
}

static WheelTimer2DNode* WheelTimer2DNode_FindInsert(WheelTimerBucket* bucketP,
                                                   WheelTimerTics target)
{
  WheelTimer2DNode *nodeP;
  WheelTimerLink *nextP;

  /* Lets find the right place to insert, in the order of target_time */
  for (nextP = bucketP; nextP->prevP != bucketP; nextP = nextP->prevP)
  {
    nodeP = (WheelTimer2DNode*)nextP->prevP;
    /* Skip the ones with bigger target time (going backwards) */
    if (nodeP->target_time > target)
      continue;

    /* If the column already exists, return it */
    if (nodeP->target_time == target)
      return nodeP;

    /* If the column does not exist, break out so that we can create it */
    break;
  }

  /* Create and initialize the new column */
  if ((nodeP = WheelTimer2DNode__Allocate()) != NULL)
  {
    nodeP->target_time  = target;
    nodeP->h_link.nextP = nodeP->h_link.prevP = &nodeP->h_link;
    nodeP->v_link.nextP = nodeP->v_link.prevP = &nodeP->v_link;
    /* insert the new column node into the row before nextP */
    WheelTimerLink_Link(&nodeP->h_link, &nodeP->h_link, nextP);
  }

  return nodeP;
}

static WheelTimerResult WheelTimerBucket_InsertTo2DList(WheelTimerBucket* bucketP,
                                                      WheelTimerElement *elementP)
{
  WheelTimer2DNode *nodeP;

  /* Find the right column to insert. Create if one doesn't exist */
  if ((nodeP = WheelTimer2DNode_FindInsert(bucketP, elementP->target_time)) != NULL)
  {
    /* Insert the element at the end of the column */
    WheelTimerLink_Link(&elementP->link, &elementP->link, &nodeP->v_link);
    return WheelTimerSuccess;
  }

  return WheelTimerOutOfMemory;
}

static WheelTimerResult WheelTimerBucket_RemoveFrom2DList(WheelTimerBucket* bucketP,
                                                        WheelTimerElement *elementP)
{
  /* Save previous node to figure out if this is the last element of the column */
  WheelTimerLink *prevP = elementP->link.prevP;

  /* Unlink the element from the vertical list */
  WheelTimerLink_Unlink(&elementP->link, &elementP->link);

  /* If this leaves prevP pointing to itself, column is empty */
  if (prevP->nextP == prevP)
  {
    /* This also means that prevP actually is the &vlink of the column head node */
    /* Get the column head node and get rid of it */
    WheelTimer2DNode_Delete(WheelTimer2DNode__GetNodeFromVLink(prevP));
  }

  return WheelTimerSuccess;
}

static WheelTimerResult WheelTimerBucket_GetReadyItemsFrom2DList(WheelTimerBucket *bucketP,
                                                               WheelTimerTics time,
                                                               WheelTimerLink *readyP)
{
  /* While bucket is not emty */
  while (bucketP->nextP != bucketP)
  {
    /* Get the first column node */
    WheelTimer2DNode *nodeP = (WheelTimer2DNode*)bucketP->nextP;
    WheelTimerLink *headP, *tailP;

    /* Break out if the column is not ready */
    if (nodeP->target_time > time)
      break;

    /* Unlink the entire elements list from the column node */
    WheelTimerLink_Unlink(headP = nodeP->v_link.nextP, tailP = nodeP->v_link.prevP);
    /* Link it to the ready list */
    WheelTimerLink_Link(headP, tailP, readyP);
    /* Get rid of the column head node */
    WheelTimer2DNode_Delete(nodeP);
  }

  return WheelTimerSuccess;
}

static void WheelTimer_InstalBucketPlugin(WheelTimer *timerP,
                                          WheelTimerBucketPlugin *pluginP)
{
  /* Initialize the bucket plugin */
  timerP->bucket_plugin.initFn          = pluginP->initFn;
  timerP->bucket_plugin.doneFn          = pluginP->doneFn;
  timerP->bucket_plugin.printFn         = pluginP->printFn;
  timerP->bucket_plugin.insertFn        = pluginP->insertFn;
  timerP->bucket_plugin.removeFn        = pluginP->removeFn;
  timerP->bucket_plugin.getReadyItemsFn = pluginP->getReadyItemsFn;

  /* Call the bucket initialize function if provided */
  if (timerP->bucket_plugin.initFn)
    (*timerP->bucket_plugin.initFn)();
}

/*******************************  APIS Start Here   ******************************/

/* ----------------------------- WheelTimer_Create ----------------------------- */
/*Function: Creates a new WheelTimer with one of the built-in bucket plugins     */
/*Arguments: size: Number of slots requested for the timer wheel                 */
/*           timeout: The function to be called when an element times out        */
/*           printout: The function to be used for printing out the elements     */
/*           bucket_type: How the user wants the timer buckets to be implemented */
/*Returns  : The id of the newly created timer upon success, zero upon failure   */
/* ----------------------------------------------------------------------------- */
WheelTimerId WheelTimer_Create(UINT32 size,
                 WheelTimerCallback timeout,
                 WheelTimerPrintCallback printout,
                 WheelTimerBucketType bucket_type)
{
  WheelTimer *timerP;
  WheelTimerBucketPlugin bucket_plugin;

  /* If this is the first timer to be ever created, initialize the head link */
  if (!WheelTimersHead.prevP || !WheelTimersHead.nextP)
     WheelTimersHead.prevP  =  WheelTimersHead.nextP = &WheelTimersHead;

  /* If we have a valid size and timeout function, Try allocating the timer */
  if ((size) && (timeout) && (timerP = WheelTimer_Allocate(size)))
  {
    /* All good. Initialize the timer */
    timerP->num_slots = size;
    timerP->timeout_callback = timeout;
    timerP->printout_callback = printout;

    /* Initialize the bucket plugin with appropriate routines by type */
    switch (bucket_type)
    {
      default:
      case WheelTimer1DLinkedList:
        bucket_plugin.initFn   = NULL;
        bucket_plugin.doneFn   = NULL;
        bucket_plugin.printFn  = &WheelTimerBucket_Print1DList;
        bucket_plugin.insertFn = &WheelTimerBucket_InsertTo1DList;
        bucket_plugin.removeFn = &WheelTimerBucket_RemoveFrom1DList;
        bucket_plugin.getReadyItemsFn = &WheelTimerBucket_GetReadyItemsFrom1DList;
        break;
      case WheelTimer2DLinkedList:
        bucket_plugin.initFn   = &WheelTimerBucket_Initialize2DList;
        bucket_plugin.doneFn   = &WheelTimerBucket_CleanUp2DList;
        bucket_plugin.printFn  = &WheelTimerBucket_Print2DList;
        bucket_plugin.insertFn = &WheelTimerBucket_InsertTo2DList;
        bucket_plugin.removeFn = &WheelTimerBucket_RemoveFrom2DList;
        bucket_plugin.getReadyItemsFn = &WheelTimerBucket_GetReadyItemsFrom2DList;
        break;
    }

    /* Instal the bucket plugin and return */
    WheelTimer_InstalBucketPlugin(timerP, &bucket_plugin);
    return (WheelTimerId)timerP;
  }

  return 0;
}

/* -------------------------- WheelTimer_AddElement ---------------------------- */
/*Function: Enqueues a new element into the WheelTimer                           */
/*Arguments: id: The TimerId of the WheelTimer to enqueue the element into.      */
/*           elementP: The element to be enqueued into the Wheel Timer.          */
/*           offset: The offset (in terms of tics) into the future when this     */
/*                   element is to be timed out. Value of zero means the element */
/*                   will go directly into the ready queue and get processed on  */
/*                   a FIFO basis.                                               */
/*Returns  : WheelTimerSuccess upon success, error code upon failure             */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_AddElement(WheelTimerId id,
                               WheelTimerElement *elementP,
                         WheelTimerTics offset)
{
  /* Convert id into timer pointer */
  WheelTimer *timerP = WheelTimer__GetTimerFromId(id);

  /* Make sure the timer and the element are valid, and not already enqueued */
  if (timerP && elementP && elementP->magic_num != WHEEL_TIMER_MAGIC_NUMBER)
  {
    elementP->timeout_callback = timerP->timeout_callback;
    elementP->printout_callback = timerP->printout_callback;

    /* Compute the absolute time when the element will timeout */
    elementP->target_time = timerP->cur_time + offset;

    /* If offset is zero, enqueue directly into the ready queue */
    if (offset == 0)
      WheelTimerLink_Link(&elementP->link, &elementP->link, &timerP->ready_queue);
    else
    {
      WheelTimerSlots slot;
      WheelTimerResult res;

      /* Find the slot on the wheel where this element would go into */
      slot = (elementP->target_time - timerP->cur_time + timerP->cur_slot)%(timerP->num_slots);

      /* Insert the element into the bucket and return error if failure */
      res = (*timerP->bucket_plugin.insertFn)(&timerP->cir_array[slot], elementP);
      if (res != WheelTimerSuccess)
        return res;
    }

    /* Enqueue success. Mark element as enqueued and return success */
    elementP->magic_num = WHEEL_TIMER_MAGIC_NUMBER;
    return WheelTimerSuccess;
  }

  return WheelTimerBadArgument;
}

/* -------------------------- WheelTimer_AddElementCallback ---------------------------- */
/*Function: Enqueues a new element into the WheelTimer with specific callback                          */
/*Arguments: id: The TimerId of the WheelTimer to enqueue the element into.      */
/*           elementP: The element to be enqueued into the Wheel Timer.          */
/*           offset: The offset (in terms of tics) into the future when this     */
/*                   element is to be timed out. Value of zero means the element */
/*                   will go directly into the ready queue and get processed on  */
/*                   a FIFO basis.                                               */
/*           timeout_callback: The function to be called when an element times out  */
/*           printout: The function to be used for printing out the elements     */
/*Returns  : WheelTimerSuccess upon success, error code upon failure             */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_AddElementCallback(WheelTimerId id,
                               WheelTimerElement *elementP,
                         WheelTimerTics offset, WheelTimerCallback timeout_callback,
                         WheelTimerPrintCallback printout)
{
  WheelTimerResult res;

  if(!timeout_callback)
  {
    return WheelTimerBadArgument;
  }

  res = WheelTimer_AddElement(id, elementP, offset);

  if(res == WheelTimerSuccess)
  {
    elementP->timeout_callback = timeout_callback;
    elementP->printout_callback = printout;
  }

  return res;
}

/* -------------------------- WheelTimer_DelElement ---------------------------- */
/*Function: Dequeues an element from the WheelTimer                              */
/*Arguments: id: The TimerId of the WheelTimer from which to dequeue the element */
/*           elementP: The element to be dequeued from the Wheel Timer.          */
/*Returns  : WheelTimerSuccess upon success, error code upon failure             */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_DelElement(WheelTimerId id,
                                       WheelTimerElement *elementP)
{
  /* Convert id into timer pointer */
  WheelTimer *timerP = WheelTimer__GetTimerFromId(id);

  /* Make sure the timer and the element are valid, and is indeed enqueued */
  if (timerP && elementP && elementP->magic_num == WHEEL_TIMER_MAGIC_NUMBER)
  {
    /* If the element's target time is <= the current time of the wheel,
       the element must be in the ready queue */
    if (elementP->target_time <= timerP->cur_time)
      WheelTimerLink_Unlink(&elementP->link, &elementP->link);
    else
    {
      WheelTimerSlots slot;
      WheelTimerResult res;

      /* Find the slot on the wheel where this element would go into */
      slot = (elementP->target_time - timerP->cur_time + timerP->cur_slot)%(timerP->num_slots);

      /* Remove the element from the bucket and return error if failure */
      res = (*timerP->bucket_plugin.removeFn)(&timerP->cir_array[slot], elementP);
      if (res != WheelTimerSuccess)
        return res;
    }

    /* Dequeue success. Mark element as dequeued and return success */
    elementP->magic_num = WHEEL_TIMER_TRAGIC_NUMBER;
    return WheelTimerSuccess;
  }

  return WheelTimerBadArgument;
}

/* ------------------------ WheelTimer_ReTimeElement --------------------------- */
/*Function: Changes the target time of an already enqued element                 */
/*Arguments: id: The TimerId of the WheelTimer in which the element resides.     */
/*           elementP: The element whose target time should be updated.          */
/*           offset: The new offset (in terms of tics) into the future when this */
/*                   element is to be timed out.                                 */
/*Returns  : WheelTimerSuccess upon success, error code upon failure             */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_ReTimeElement(WheelTimerId id,
                                          WheelTimerElement *elementP,
                                          WheelTimerTics offset)
{
  WheelTimerResult res = WheelTimer_DelElement(id, elementP);

  if (res == WheelTimerSuccess)
    res  = WheelTimer_AddElementCallback(id, elementP, offset,
                      elementP->timeout_callback,
                      elementP->printout_callback);
  return res;
}

/* -------------------------- WheelTimer_UpdateTic ----------------------------- */
/*Function: Rotates the timer wheel and times out the elements which are due.    */
/*Arguments: id: The TimerId of the WheelTimer that is to be rotated.            */
/*           tics: The number of slots the wheel needs to be rotated.            */
/*           budget: Max number of elements that can be timed out by this call.  */
/*                   If there are more elements, the function will suspend and   */
/*           return. The remaining elements will accumulate in the ready */
/*                   queuebe and will be processed during the subsequent calls   */
/*                   on a FIFO basis. Value of zero means a budget of infinity.  */
/*Returns  : WheelTimerBadArgument if invalid TimerId is detected.               */
/*           WheelTimerOutOfBudget if the return is due to a budget exhaustion,  */
/*               ie, if there are more elements that are ready to be timed out   */
/*               than what the budget would allow.                               */
/*           WheelTimerSuccess if the return is due to exhaustion of the ready   */
/*               queue, ie if all elements that are due to be timeout at this    */
/*               time are timed out.                                             */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_UpdateTic(WheelTimerId id, UINT32 budget,
                                      WheelTimerTics tics)
{
  /* Convert id into timer pointer */
  WheelTimer *timerP = WheelTimer__GetTimerFromId(id);

  /* If the id is valid */
  if (timerP)
  {
    /* Rotate the wheel as many as tic number of slots */
    while (tics --)
    {
      /* Update the state of the wheel */
      timerP->cur_time = (timerP->cur_time + 1);
      timerP->cur_slot = (timerP->cur_slot + 1)%(timerP->num_slots);

      /* Remove the current ready list from the wheel and put it in the ready queue */
      (*timerP->bucket_plugin.getReadyItemsFn)(&timerP->cir_array[timerP->cur_slot], timerP->cur_time, &timerP->ready_queue);
    }

    /* Now process the elements from the ready queue while its not empty */
    while (timerP->ready_queue.nextP != &timerP->ready_queue)
    {
      WheelTimerElement *elementP = (WheelTimerElement*)timerP->ready_queue.nextP;

      /* Remove the element from ready queue */
      WheelTimerLink_Unlink(&elementP->link, &elementP->link);
      /* Mark the element as dequeued before calling callback */
      elementP->magic_num = WHEEL_TIMER_TRAGIC_NUMBER;
      /* Call callback. Element could get destroyed by callback */
      (*elementP->timeout_callback)(elementP->data);

      /* If there is not enough budget for the next element, return indication */
      if (--budget == 0)
        return WheelTimerOutOfBudget;
    }

    return WheelTimerSuccess;
  }

  return WheelTimerBadArgument;
}

/* --------------------------- WheelTimer_Destroy ------------------------------ */
/*Function: Dequeues all elements and then destroys the Wheel Timer.             */
/*Arguments: id: The TimerId of the WheelTimer that is to be destroyed.          */
/*Returns  : WheelTimerSuccess upon success, error code upon failure             */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_Destroy(WheelTimerId id)
{
  /* Convert id into timer pointer */
  WheelTimer *timerP = WheelTimer__GetTimerFromId(id);

  /* if the id is valid */
  if (timerP)
  {
    WheelTimerSlots slot;

    /* For each bucket in the timer */
    for (slot = 0; slot < timerP->num_slots; slot ++)
    {
      /* Remove everything from the bucket and append it to the ready queue */
      (*timerP->bucket_plugin.getReadyItemsFn)(&timerP->cir_array[slot], 0xFFFFFFFF, &timerP->ready_queue);
    }

    /* Now remove the elements from the ready queue while its not empty */
    while (timerP->ready_queue.nextP != &timerP->ready_queue)
    {
      WheelTimerElement *elementP = (WheelTimerElement*)timerP->ready_queue.nextP;

      /* Remove the element from ready queue */
      WheelTimerLink_Unlink(&elementP->link, &elementP->link);
      /* Mark the element as dequeued */
      elementP->magic_num = WHEEL_TIMER_TRAGIC_NUMBER;
    }

    /* Call the bucket finish routine if provided */
    if (timerP->bucket_plugin.doneFn)
      (*timerP->bucket_plugin.doneFn)();

    /* Say goodbye to the timer */
    WheelTimer_Free(timerP);
    return WheelTimerSuccess;
  }

  return WheelTimerBadArgument;
}

/* -------------------------- WheelTimer_isElementEnqueued ---------------------- */
/*Function: Checks whether an element is already enqueued in to the WheelTimer                    */
/*Arguments:  elementP: The element to be checked                            */
/*Returns  : WheelTimerSuccess if element is already enqueued else  WheelTimerFailure          */
/* ----------------------------------------------------------------------------- */
WheelTimerResult WheelTimer_IsElementEnqueued(WheelTimerElement *elementP)
{
  if (elementP && elementP->magic_num == WHEEL_TIMER_MAGIC_NUMBER)
    return WheelTimerSuccess;

  return WheelTimerFailure;
}

/* -------------------------- WheelTimer_GetTimeToExpire ------------------------------------------ */
/* Function  : Gets the time remaining to expire for a element in the wheel timer                   */
/* Arguments : id          : wheel timer id                                                         */
/*             elementP    : The element to be checked                                        */
/*             time        : Return value in time ticks                                             */
/* Returns   : WheelTimerSuccess if element present and returns time in the supplied param and      */
/*             WheelTimerFailure  incase of failure                                                 */
/* -----------------------------------------------------------------------------------------------  */
WheelTimerResult WheelTimer_GetTimeToExpire(WheelTimerId id, WheelTimerElement *elementP, WheelTimerTics *time)
{
  /* Convert id into timer pointer */
  WheelTimer *timerP = WheelTimer__GetTimerFromId(id);

  /* Make sure the time, timer and the element are valid, and is already enqueued */
  if (time && timerP && elementP && elementP->magic_num == WHEEL_TIMER_MAGIC_NUMBER)
  {
    *time = (elementP->target_time - timerP->cur_time);
    return WheelTimerSuccess;
  }
  return WheelTimerBadArgument;
}
