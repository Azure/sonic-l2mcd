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

#endif /* _HASH_GROW_H_ */





