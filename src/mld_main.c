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

#include "l2mcd_portdb.h"
#include "l2mcd_mld_utils.h"
#include "mld_vlan_db.h"
#include "l2mcd_dbsync.h"

extern L2MCD_AVL_TREE *mld_portdb_tree;
extern MCGRP_CLASS      mld;
extern MCGRP_CLASS      Mld0, *pMld0;
extern MCGRP_GLOBAL_CLASS   gMld, *pgMld;


/* This function is called when a physical port w/in a logical port (VE interface) changes state (UP/DN)
 * If UP, we allocate and initialize the necessary data structures
 * If DN, we drop the port's memberships in the various groups active on the system.
 */
void mld_vport_state_notify (UINT16   vir_port_id, 
        UINT32   phy_port_id, 
        BOOLEAN  up,
        MCGRP_CLASS *mld)
{
    MCGRP_L3IF        *mld_vport;   
    MCGRP_PORT_ENTRY  *mld_pport;
    UINT32             primary_phy_port;
    char                *prt_str     = (IS_IGMP_CLASS(mld) ? "IGMP" : "MLD");
    uint32_t  afi = (IS_IGMP_CLASS(mld) ? MCAST_IPV4_AFI:MCAST_IPV6_AFI);
    unsigned char port_type = 0;

    if (!mld || !mld->enabled || !MCGRP_IS_VALID_INTF(vir_port_id))
        return;
    port_type = portdb_get_port_type(mld_portdb_tree, vir_port_id);
    if (!is_virtual_port(vir_port_id) && !(port_type == INTF_MODE_L3))
    {

        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s.ERR: mld_vport_state_notify() invoked for non-virtual port %s", prt_str,
                mld_get_if_name_from_port(vir_port_id));
        return;
    }

    L2MCD_VLAN_LOG_INFO(vir_port_id,"%s:%d:[vlan:%d] Port %s:  %s event for phy-port of VE-port %s phy_port:%d", __FUNCTION__, __LINE__,vir_port_id,
            mld_get_if_name_from_ifindex(phy_port_id), (up ? "UP" : "DN"),
            mld_get_if_name_from_port(vir_port_id),phy_port_id);
    mld_vport = IS_IGMP_CLASS(mld) ? gIgmp.port_list[vir_port_id] : gMld.port_list[vir_port_id];


    if (mld_vport == NULL)
    {
        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s: [ Port %s/%s ] BUG !!!! Got Port UP event for a NULL vir port", prt_str,
                mld_get_if_name_from_ifindex(phy_port_id), mld_get_if_name_from_port(vir_port_id));
        return;
    }
    /*trunk_primary_port() giving the same port */
    primary_phy_port = phy_port_id;

    mld_pport = mcgrp_find_phy_port_entry(mld, mld_vport, primary_phy_port);
    if (mld_pport == NULL)
    {
        if (! up)
            return;
        // This port must have just been added to the VLAN; create an entry for it
        mld_pport = mcgrp_add_phy_port(mld, mld_vport, primary_phy_port);

        if (mld_pport == NULL)
        {
            L2MCD_VLAN_LOG_ERR(vir_port_id,"%s.ERR: [ Port %s/%s ] Failed to allocate for phy-port\n",prt_str,
                    mld_get_if_name_from_ifindex(phy_port_id), 
                    mld_get_if_name_from_port(vir_port_id));
            return;
        }

        L2MCD_VLAN_LOG_ERR(vir_port_id,"%s.ERR: [ Port %s/%s ] : Created phy-port\n",prt_str,
                mld_get_if_name_from_ifindex(primary_phy_port), mld_get_if_name_from_port(mld_vport->vir_port_id));
    }

    // Save the state of the port
    mld_pport->is_up = up;

    if (up)
    {
        // We would like to send out queries on this port in order to learn
        // membership information on this port. So start the query process
        mcgrp_start_query_process(mld, mld_pport, vir_port_id, primary_phy_port);

        mcgrp_activate_static_groups(mld, vir_port_id, primary_phy_port);
        mcgrp_activate_l2_static_groups(mld, vir_port_id, primary_phy_port);
        if ((is_mld_snooping_enabled(mld_vport, afi) &&
                    is_mld_snooping_querier_enabled(mld_vport)) ||
                is_mld_l3_configured(mld_vport)) {


            {    
                if ((afi == MCAST_IPV6_AFI) && IP6_IS_ADDRESS_UNSPECIFIED(mld_vport->querier_router.ip.v6addr.address)) {
                   //MLD
                } else {
                    L2MCD_LOG_INFO("%s() igmp_send_general_query", __FUNCTION__);
                    if (!mld_vport->querier_router.ip.v4addr || is_mld_l3_configured(mld_vport))
                        igmp_send_general_query(mld, mld_vport->vir_port_id,
                                mld_pport->phy_port_id, (UINT8) mld_vport->oper_version,
                                0, (mld_vport->max_response_time * 1000));
                }
            }
        }
    }
    else
    {
        // A port in a VE just went down.
        // If this is a trunked port and the trunk is still up, ignore the event
        if (trunk_port_state(phy_port_id) != TRUNK_NONE)
        {
            TRUNK_ID trunk_id;
            if ((trunk_id = trunk_id_get(phy_port_id)) != INVALID_TRUNK_ID &&
                    is_trunk_up(trunk_id))
            {
                return;
            }
        }

        mcgrp_stop_phy_port(mld, mld_vport, mld_pport);
        mcgrp_delete_router_port(mld, mld_vport,  phy_port_id);
    } /* if (up) ... else ... */

} /* mld_vport_state_notify */


int mldv2_src_compare (void *keya, 
        void *keyb)
{
    IPV6_ADDRESS *src_addr_a = (IPV6_ADDRESS *)(keya);
    IPV6_ADDRESS *src_addr_b = (IPV6_ADDRESS *)(keyb);

    if (IP6_ARE_ADDRESSES_SAME(src_addr_a->address, src_addr_b->address))
    {
        return 0;
    }

    return (IP6_IS_ADDRESS_LESS(src_addr_a->address, src_addr_b->address) ? -1 : 1);
}


void mldv2_src_assign (void *keya, void *keyb)
{
    MCGRP_SOURCE* to_src = (MCGRP_SOURCE*)((unsigned long)keya - 4); 
    mcast_set_ipv6_addr(&to_src->src_addr,(IPV6_ADDRESS *) keyb);
    to_src->src_timer = 0;
    to_src->retx_cnt  = 0;
    to_src->include_in_query = FALSE;
    static int to_src_clnt_addr_offset=M_AVLL_OFFSETOF(MCGRP_CLIENT, clnt_addr);
    to_src->clnt_tree= L2MCD_AVL_CREATE(mcgrp_addr_cmp_cb_param, (void *) &to_src_clnt_addr_offset, NULL);
    return;
}


MCGRP_CLASS *g_mld_destroy;

void mldv2_src_destroy(generic_pool_struct  *pool, void  *item)
{
    MCGRP_CLASS *mld = g_mld_destroy;

    if (item== NULL)
        return;

    mcgrp_free_source(mld, (MCGRP_SOURCE*) item);
}

SORTED_LINKLIST_KEYINFO mldv2_src_keyinfo =
{
    sizeof(IPV6_ADDRESS), /* Key size - size of IPv6 address */
    mldv2_src_compare,
    mldv2_src_assign,
    mldv2_src_destroy,  
    NULL,
    NULL
};


void dump_mcgrp_class (uint32_t afi)
{
    char * protocol_name = (afi == MLD_IP_IPV6_AFI ? "MLD" : "IGMP");
    MCGRP_CLASS  *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, MLD_DEFAULT_VRF_ID);
    if (!mld) {
        L2MCD_CLI_PRINT("No MCGRP_CLASS found for %s\n", protocol_name);
        return;
    }
    L2MCD_CLI_PRINT( "dumping MCGRP_CLASS for %s\n", protocol_name);
    L2MCD_CLI_PRINT( "struct MCGRP_CLASS  *inst_fwd : 0x%p\n", mld->inst_fwd);
    L2MCD_CLI_PRINT( "struct MCGRP_CLASS  *inst_bwd : 0x%p\n", mld->inst_bwd);
    L2MCD_CLI_PRINT( "VRF_INDEX                     : %d\n", mld->vrf_index);
    L2MCD_CLI_PRINT( "query_interval_time : %d\n", mld->query_interval_time);
    L2MCD_CLI_PRINT( "cfg_query_interval_time : %d\n", mld->cfg_query_interval_time);
    L2MCD_CLI_PRINT( "max_response_time : %d\n", mld->max_response_time);
    L2MCD_CLI_PRINT( "group_membership_time : %d\n", mld->group_membership_time);
    L2MCD_CLI_PRINT( "older_host_present_time  : %d\n", mld->older_host_present_time);
    L2MCD_CLI_PRINT( "LMQ_interval : %d\n", mld->LMQ_interval);
    L2MCD_CLI_PRINT( "static_group_timer : %d\n", mld->static_group_timer);
    L2MCD_CLI_PRINT( "cfg_robustness_var : %d\n", mld->cfg_robustness_var);
    L2MCD_CLI_PRINT( "robustness_var : %d\n", mld->robustness_var);
    L2MCD_CLI_PRINT( "enabled : %d\n", mld->enabled);
    L2MCD_CLI_PRINT( "LMQ_count : %d\n", mld->LMQ_count);
    L2MCD_CLI_PRINT( "cfg_version : %d\n", mld->cfg_version);
    L2MCD_CLI_PRINT( "oper_version : %d\n", mld->oper_version);
    L2MCD_CLI_PRINT( "afi : %d\n",  mld->afi);
    L2MCD_CLI_PRINT( "printing %s statistics\n", protocol_name);
    L2MCD_CLI_PRINT( "---------------------- \n");

    L2MCD_CLI_PRINT( "\nrouter_alert_check_disable : %d\n", mld->router_alert_check_disable);
    L2MCD_CLI_PRINT( "static_mcgrp_list_head : 0x%p\n", mld->static_mcgrp_list_head);
    L2MCD_CLI_PRINT( "max_groups : %d\n", mld->max_groups);
    L2MCD_CLI_PRINT( "first_time_init : %d\n", mld->first_time_init);
    L2MCD_CLI_PRINT( "WheelTimerId : %lu\n", mld->mcgrp_wtid); // to be expanded later
    L2MCD_CLI_PRINT( "rx_bad_if : %d\b", mld->rx_bad_if);
    L2MCD_CLI_PRINT( "group_tree : 0x%p\n", &mld->group_tree);
    L2MCD_CLI_PRINT( "ngroups : %d\n", mld->ngroups);
    return;   
}

void mldv2_sorted_linklist_minus (MCGRP_CLASS              *mld,
        generic_pool_struct      *pool,
        SORTED_LINKLIST_KEYINFO  *key_info,
        SORTED_LINKLIST         **dest_p, 
        SORTED_LINKLIST          *src)
{
    g_mld_destroy = mld;
    sorted_linklist_minus(pool, key_info, dest_p, src);
}


void mldv2_sorted_linklist_keep_common (MCGRP_CLASS              *mld,
        generic_pool_struct      *pool,
        SORTED_LINKLIST_KEYINFO  *key_info,
        SORTED_LINKLIST         **dest_p, 
        SORTED_LINKLIST          *src)
{
    g_mld_destroy = mld;
    sorted_linklist_keep_common(pool, key_info, dest_p, src);
}


void mldv2_sorted_linklist_free_list (MCGRP_CLASS              *mld,
        generic_pool_struct      *pool,
        SORTED_LINKLIST_KEYINFO  *key_info,
        SORTED_LINKLIST          *src)
{
    g_mld_destroy = mld;
    sorted_linklist_free_list(pool, key_info, src);
}

