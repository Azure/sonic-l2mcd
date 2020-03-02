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

extern struct list *snooping_enabled_vlans[MCAST_AFI_MAX];
struct list *pending_interface;

void l2mcd_port_state_notify_handler(l2mcd_if_tree_t *l2mcd_if_tree,int state_up)
{
    VRF_INDEX vrf_index = L2MCD_DEFAULT_VRF_IDX;
	mld_vlan_node_t *vlan_node = NULL;
	struct listnode *node = NULL;
	int afi = L2MCD_IPV4_AFI;
    int port = l2mcd_if_tree->ifid;
	MCGRP_CLASS         *mcgrp = NULL; 

	L2MCD_LOG_NOTICE("%s(%d)port %d %s state %d", FN, LN, port,mld_get_if_name_from_port(port), state_up);
    mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index);
    LIST_LOOP(snooping_enabled_vlans[afi - 1], vlan_node, node) 
    {
        if (is_mld_vlan_snooping_enabled(vlan_node, afi)) 
        { 

            if (mld_is_port_member_of_vlan(vlan_node, port)) 
            {
                L2MCD_VLAN_LOG_INFO(vlan_node->ivid, "%s:%d:[vlan:%d] port: %s[%d] state_up:%d ivid %d snp_enbl %d mbr_vlan %d",
                        FN,LN, vlan_node->ivid, l2mcd_if_tree->iname, port, state_up, vlan_node->ivid,
                        is_mld_vlan_snooping_enabled(vlan_node, afi),
                        mld_is_port_member_of_vlan (vlan_node, port));
                mld_protocol_port_state_notify(vlan_node, afi, mcgrp, port, state_up);
            }
        }
    }
	return;
}

/*
 * IF Tree  
 */
int l2mcd_add_kif_to_if(char *ifname, uint32_t ifid, int fd, struct event *igmp_rx_event, int po_id, int vid, int op_code, int oper)
{
    uint32_t kif;
    kif = if_nametoindex(ifname);
    l2mcd_if_tree_t *l2mcd_if_tree1, *l2mcd_if_tree2;
    int new_entry=0;

    l2mcd_if_tree1 = l2mcd_kif_to_if(kif);
    if (!l2mcd_if_tree1)
    {
        l2mcd_if_tree1 = (l2mcd_if_tree_t *)calloc(1, (sizeof(l2mcd_if_tree_t)));
        if (!l2mcd_if_tree1) return -1;
        l2mcd_if_tree2 = (l2mcd_if_tree_t *)calloc(1, (sizeof(l2mcd_if_tree_t)));
        if (!l2mcd_if_tree2) 
        { 
            free(l2mcd_if_tree1); 
            return -1;
        }
        M_AVLL_INIT_NODE(l2mcd_if_tree1->node);
        M_AVLL_INIT_NODE(l2mcd_if_tree2->node);
        new_entry=1;
    }
    else
    {
         l2mcd_if_tree2 = l2mcd_if_to_kif(ifid);
         if (!l2mcd_if_tree2) 
         {
            L2MCD_INIT_LOG("Err kif_to_if: if:%d  get found. if_to_kif exists  \n",ifid);
            return -1;
         } 
    }
    
    l2mcd_if_tree1->kif = l2mcd_if_tree2->kif = kif;
    if (oper != -1)
    {
        l2mcd_if_tree1->oper = l2mcd_if_tree2->oper = oper;
    }
    if (po_id != -1)
    {
        l2mcd_if_tree1->po_id = l2mcd_if_tree2->po_id = po_id;
    }
    if (fd !=-1)
    {
        l2mcd_if_tree1->sock_fd = l2mcd_if_tree2->sock_fd = fd;
        l2mcd_if_tree1->igmp_rx_event=l2mcd_if_tree2->igmp_rx_event=igmp_rx_event;
    }
    if (vid != -1)
    {
        if (op_code) 
        {
            L2MCD_VLAN_BM_SET(l2mcd_if_tree2->bm, vid);
            L2MCD_VLAN_BM_SET(l2mcd_if_tree1->bm, vid);
            L2MCD_LOG_DEBUG("set vid idx:%d pos:%d",vid, L2MCD_VLAN_BM_IDX(vid), L2MCD_VLAN_BM_POS(vid));
        }
        else
        {
            L2MCD_VLAN_BM_CLR(l2mcd_if_tree2->bm,vid);
            L2MCD_VLAN_BM_CLR(l2mcd_if_tree1->bm, vid);
            L2MCD_LOG_DEBUG("clear vid idx:%d pos:%d",vid, L2MCD_VLAN_BM_IDX(vid), L2MCD_VLAN_BM_POS(vid));
        } 
    }

    if (new_entry)
    {
        l2mcd_if_tree1->ifid = l2mcd_if_tree2->ifid = ifid;
        memcpy(l2mcd_if_tree1->iname, ifname, L2MCD_IFNAME_SIZE);
        memcpy(l2mcd_if_tree2->iname, ifname,L2MCD_IFNAME_SIZE);
        if (!M_AVLL_INSERT(g_l2mcd_kif_to_if_tree, l2mcd_if_tree1))
        {
            L2MCD_INIT_LOG("%s AVL Insert Error: if_to_kif: kif:%d if:%d iname:%s sk:%d", __FUNCTION__, l2mcd_if_tree1->ifid,l2mcd_if_tree1->kif, l2mcd_if_tree1->iname, l2mcd_if_tree1->sock_fd);
        }
        if (!M_AVLL_INSERT(g_l2mcd_if_to_kif_tree, l2mcd_if_tree2))
        {
            L2MCD_INIT_LOG("%s AVL Insert Error: if_to_kif: kif:%d if:%d iname:%s sk:%d", __FUNCTION__, l2mcd_if_tree2->kif,l2mcd_if_tree2->ifid, l2mcd_if_tree2->iname, l2mcd_if_tree2->sock_fd); 
        }
  
        L2MCD_INIT_LOG("%s kif_to_if: kif:%d if:%d iname:%s sk:%d ev:%p",
               __FUNCTION__, l2mcd_if_tree1->ifid,l2mcd_if_tree1->kif, l2mcd_if_tree1->iname, l2mcd_if_tree1->sock_fd,l2mcd_if_tree1->igmp_rx_event);
        L2MCD_INIT_LOG("%s if_to_kif: if:%d kif:%d iname:%s sk:%d ev:%p",
               __FUNCTION__, l2mcd_if_tree2->kif,l2mcd_if_tree2->ifid, l2mcd_if_tree2->iname, l2mcd_if_tree2->sock_fd,l2mcd_if_tree1->igmp_rx_event); 
    }
    return 0;
}

l2mcd_if_tree_t* l2mcd_kif_to_if(uint32_t kif)
{
    return(M_AVLL_FIND(g_l2mcd_kif_to_if_tree, &kif));
}

l2mcd_if_tree_t* l2mcd_if_to_kif(uint32_t ifid)
{
    return(M_AVLL_FIND(g_l2mcd_if_to_kif_tree, &ifid));
}

l2mcd_if_tree_t* l2mcd_kif_to_rx_if(uint32_t kif)
{
    l2mcd_if_tree_t *l2mcd_if_tree;
    l2mcd_if_tree = l2mcd_kif_to_if(kif);
    if (!l2mcd_if_tree) return NULL;
    if (l2mcd_if_tree->po_id)
    {
        return (l2mcd_if_to_kif(l2mcd_if_tree->po_id));
    
    }
    return l2mcd_if_tree;
}

int l2mcd_portstate_update(int kif, int state, char *iname)
{
    l2mcd_if_tree_t *l2mcd_if_tree1, *l2mcd_if_tree2; 

    l2mcd_if_tree1 = l2mcd_kif_to_if(kif);
    if (l2mcd_if_tree1)
    {
        l2mcd_if_tree2=l2mcd_if_to_kif(l2mcd_if_tree1->ifid);
    }
    if (l2mcd_if_tree1 && l2mcd_if_tree2)
    {
        l2mcd_if_tree1->oper = state;
        l2mcd_if_tree2->oper = state;
        l2mcd_port_state_notify_handler(l2mcd_if_tree2, state);
        L2MCD_LOG_NOTICE("%s kif:%d port:%s lif:%d kif:%d state:%s",
            __FUNCTION__, kif, l2mcd_if_tree2->iname, l2mcd_if_tree2->ifid,l2mcd_if_tree2->kif, l2mcd_if_tree2->oper?"UP":"DOWN");
        return 0;
    }
    else
    {
        L2MCD_LOG_NOTICE("%s Port:%s, kif:%d state:%d if_tree not found", __FUNCTION__, iname, kif, state);
    }
    
    return -1;

}

int l2mcd_port_list_update(char *pnames, int oper_state, int is_add) 
{
    int ifidx, kif, rc;
    l2mcd_if_tree_t *l2mcd_if_tree;
    struct event *igmp_rx_event=NULL;
    int sock_fd;
    
    ifidx = portdb_get_portindex_from_ifname(pnames);

    if (ifidx<=0)
    {
        //This can be a breakout port or similar which is yet to be added to db list
        return -1;
    }
    l2mcd_if_tree = l2mcd_if_to_kif(ifidx);
    kif = if_nametoindex(pnames);
    L2MCD_INIT_LOG("%s PortInfo RX: %s, ifidx:%d oper:%d is_add:%d is_lag:%d, kif:%d", 
         __FUNCTION__, pnames,  ifidx, oper_state, is_add, L2MCD_IFINDEX_IS_LAG(ifidx), kif);
    if (L2MCD_IFINDEX_IS_LAG(ifidx)) 
    {
        /*
         * socket/event is not created for LAG interface. Packet received on member port is 
         * mapped to corresponding Po and is processed.
         */
        L2MCD_INIT_LOG("LAG  ifidx:%d %s", ifidx,pnames);
        if (!is_add) 
		{
		    l2mcd_del_if_tree(ifidx); 
			return 0;
		}
        l2mcd_add_kif_to_if(pnames, ifidx, -1, NULL, -1, -1, -1, oper_state);
        return 0; 
    }
    if (!is_add) 
    {
       if (l2mcd_if_tree)
       {
            l2mcd_igmprx_sock_close(pnames, l2mcd_if_tree->sock_fd, l2mcd_if_tree->igmp_rx_event);
            l2mcd_del_if_tree(ifidx);
       }
       return 0;
    }
    
    if (kif <=0)
    {
        L2MCD_INIT_LOG("%s PortInfo RX: %s, if:%d is_add:%d oper_state:%d not available",
                        __FUNCTION__, pnames,kif,is_add,oper_state);
        return -1;
    }
    if (l2mcd_if_tree && l2mcd_if_tree->sock_fd)
    {
        L2MCD_INIT_LOG("%s if:%s(%d) rx_sock:%d exists", __FUNCTION__, pnames, ifidx, l2mcd_if_tree->sock_fd);
        return 0;
    }
    igmp_rx_event = l2mcd_igmprx_sock_init(&sock_fd, pnames);
    if (!igmp_rx_event)
    {
        L2MCD_INIT_LOG("socket create failed for RX: %s, if:%d",pnames,kif);
    }
    rc=l2mcd_add_kif_to_if(pnames, ifidx, sock_fd, igmp_rx_event, -1, -1, -1, oper_state);
    return rc;
}


int l2mcd_del_if_tree(uint32_t ifid)
{

    l2mcd_if_tree_t *l2mcd_if_tree = M_AVLL_FIND(g_l2mcd_if_to_kif_tree, &ifid);
    l2mcd_if_tree_t *l2mcd_if_tree2;
    uint32_t kif;
    if (l2mcd_if_tree)
    {
        kif = l2mcd_if_tree->kif;
        l2mcd_if_tree2 = M_AVLL_FIND(g_l2mcd_kif_to_if_tree, &kif);
        M_AVLL_DELETE(g_l2mcd_if_to_kif_tree, l2mcd_if_tree);
        free(l2mcd_if_tree);
        if (l2mcd_if_tree2)
        {
            M_AVLL_DELETE(g_l2mcd_kif_to_if_tree, l2mcd_if_tree2);
            free(l2mcd_if_tree2);
        }
    }
    return 0;
}

//GNU AVL comparison
int l2mcd_avl_compare_u32(const void *ptr1, const void *ptr2, void *params)
{
    int offset = *(int *) params;
    uint32_t key1 = *(uint32_t *) (ptr1);
    uint32_t key2 = *(uint32_t *) (ptr2);
    L2MCD_LOG_DEBUG("%s keys (%d,%d) offset:%d ptrs(%p,%p)",__FUNCTION__, key1, key2, offset, ptr1, ptr2);
    if (key1 > key2)
    {
        return 1;
    }
    else if(key1 < key2)
    {
        return -1;
    }
    return 0;
}
int l2mcd_avll_init()
{
    static int offset_kif=M_AVLL_OFFSETOF(l2mcd_if_tree_t, kif);
    static int offset_ifid=M_AVLL_OFFSETOF(l2mcd_if_tree_t, ifid);
    static int offset=M_AVLL_OFFSETOF(portdb_entry_t, port_index);
    g_l2mcd_kif_to_if_tree= L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &offset_kif, NULL);
    g_l2mcd_if_to_kif_tree= L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &offset_ifid, NULL);
    gMld.portdb_tree = L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &offset, NULL);
    gMld.ve_portdb_tree = L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &offset, NULL);
    L2MCD_INIT_LOG("%s kif_to_if_tree:%p keyoset:%d , if_to_kif_tree:%p, keyoset:%d",
          __FUNCTION__, g_l2mcd_kif_to_if_tree, offset_kif,g_l2mcd_if_to_kif_tree, offset_ifid);
    pending_interface = list_new();
    return 0;
}
