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

#include "l2mcd.h"
#include "l2mcd_mcast_co.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_portdb.h"

void l2mcd_port_state_notify_handler(l2mcd_if_tree_t *l2mcd_if_tree,int state_up)
{
 	return;
}

/*
 * IF Tree  
 */
int l2mcd_add_kif_to_if(char *ifname, uint32_t ifid, int fd, struct event *igmp_rx_event, int po_id, int vid, int op_code, int oper)
{
     return 0;
}

l2mcd_if_tree_t* l2mcd_kif_to_if(uint32_t kif)
{
}

l2mcd_if_tree_t* l2mcd_if_to_kif(uint32_t ifid)
{
}
l2mcd_if_tree_t* l2mcd_kif_to_rx_if(uint32_t kif)
{
    return -1;
}
int l2mcd_portstate_update(int kif, int state, char *iname)
{
}
int l2mcd_port_list_update(char *pnames, int oper_state, int is_add) 
{
}
int l2mcd_del_if_tree(uint32_t ifid)
{
    return 0;
}

int l2mcd_avl_compare_u32(const void *ptr1, const void *ptr2, void *params)
{
}
int l2mcd_avll_init()
{
    return 0;
}
