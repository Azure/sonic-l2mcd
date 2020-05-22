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
#ifndef __L2MCD_PORTDB__
#define __L2MCD_PORTDB__

#include "l2mcd_data_struct.h"
#include "hash_grow_generic.h"
#include "l2mcd_mld_port.h"
#include "l2mcd.h"
#include "l2mcd_mcast_co.h"
#define MAC_ADDR_LEN 6
#define PORTDB_DEFAULT_PORT_MTU     1500
#define PORTDB_DEFAULT_PORT_TYPE    1



typedef struct portdb_entry_s {
} portdb_entry_t;

typedef struct port_link_list_s
{
}port_link_list_t;

#endif //__L2MCD_PORTDB__
