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
#ifndef __L2MCD_DBSYNC__
#define __L2MCD_DBSYNC__
#include "l2mcd.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void l2mcsync_add_vlan_entry(uint16_t vlan_id);
extern void l2mcsync_del_vlan_entry(uint16_t vlan_id);
extern void l2mcsync_add_l2mc_entry(L2MCD_APP_TABLE_ENTRY *msg);
extern void l2mcsync_del_l2mc_entry(L2MCD_APP_TABLE_ENTRY *msg);
extern void l2mcsync_process_mrouterentry(L2MCD_APP_TABLE_ENTRY *msg);
extern void l2mcsync_init_debug_framework(void);
extern void l2mcsync_debug_print(const char *fmt, ...);
extern int l2mcd_is_peerlink(char *portname);
#ifdef __cplusplus
}/* extern "C" */
#endif

#endif
