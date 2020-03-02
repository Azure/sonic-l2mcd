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

#include "l2mcd_mcast_co.h"
#include <stdio.h>
#include "l2mcd_mld_utils.h"
#include "l2mcd_mld_port.h"

#define CU_DFLT_PIMS_PRUNE_WAIT_TIME            3
extern MCAST_GLOBAL_CLASS    gMulticast, *pgMulticast;

void igmp_reset_default_values(MCGRP_CLASS *igmp)
{
    igmp->cfg_query_interval_time = CU_DFLT_IGMP_QUERY_INTERVAL;
    igmp->query_interval_time     = CU_DFLT_IGMP_QUERY_INTERVAL;
    igmp->max_response_time       = CU_DFLT_IGMP_RESPONSE_TIME;
    igmp->group_membership_time   = CU_DFLT_IGMP_GROUP_MEMBERSHIP_TIME;
    igmp->older_host_present_time = CU_DFLT_IGMP_OLDER_HOST_PRESENT_TIME;
    igmp->robustness_var          = IGMP_DEFAULT_ROBUSTNESS_VARIABLE;
    igmp->cfg_robustness_var      = IGMP_DFLT_ROBUSTNESS;
    igmp->max_groups              = CU_DFLT_IGMP_MAX_GROUP_ADDRESS;
    igmp->pim_prune_wait_interval = CU_DFLT_PIMS_PRUNE_WAIT_TIME;
    igmp->LMQ_interval            = 1;      /* seconds */
    igmp->LMQ_count               = igmp->robustness_var;
    igmp->router_alert_check_disable = FALSE;

    igmp_set_global_version(igmp->vrf_index, IGMP_VERSION_NONE, TRUE /* force-replicate to all ports */);
}


void igmp_enable (VRF_INDEX  vrf_index,  UINT8   protocol)
{
    MCGRP_CLASS  *igmp=NULL;
    igmp = IGMP_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    if (igmp == NULL)
    {
        igmp = mcgrp_vrf_alloc(IP_IPV4_AFI, vrf_index);
        if (igmp == NULL)
        {
            L2MCD_LOG_NOTICE("%s:%d vrf allocate fail vrf %d ", __FUNCTION__, __LINE__, vrf_index);
            L2MCD_INIT_LOG("%s:%d vrf allocate fail vrf %d ", __FUNCTION__, __LINE__, vrf_index);
            return;
        }
    }

    // If IGMP needs to be initialized, do so.
    if (igmp->first_time_init == FALSE)
    {
        // If initialization fails retain the first_time flag so that we can attempt again
        if (mcgrp_initialize(IP_IPV4_AFI, igmp))
            igmp->first_time_init = TRUE;
    }
    igmp->enabled |= TRUE;

    static int group_address_offset = M_AVLL_OFFSETOF(GROUP_ENTRY, group_address.ip.v4addr);
    igmp->group_tree= L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &group_address_offset, NULL);
    L2MCD_LOG_NOTICE("%s Completed vrf:%d protocol:%d igmp:%p group_tree:%p", __FUNCTION__,vrf_index, protocol, igmp, igmp->group_tree);
    L2MCD_INIT_LOG("%s Completed vrf:%d protocol:%d igmp:%p group_tree:%p", __FUNCTION__,vrf_index, protocol,igmp, igmp->group_tree);
    return;
}


/* ================ VERSION ==================== */
// This is called to update a VE port's configuration as well as its member ports
// whenever a VE port's configuration changes either due to a change in the global
// or the VE port's version configuration.

void igmp_update_ve_member_ports (MCGRP_CLASS *igmp,
        MCGRP_L3IF  *igmp_vport,
        UINT8        version,
        BOOL         force)
{
    MCGRP_PORT_ENTRY *igmp_pport;

    igmp_pport = igmp_vport->phy_port_list;

    // Update oper_version for all member ports that do not have an explicit configuration
    for (; igmp_pport; igmp_pport = igmp_pport->next)
    { 
        if (igmp_pport->cfg_version == IGMP_VERSION_NONE)
        {
            igmp_pport->oper_version = version;
        }
        else if (force)
        {
            igmp_pport->oper_version = version;
            igmp_pport->cfg_version  = igmp_vport->cfg_version;
        }
    }
    (igmp->igmp_stats[igmp_vport->vir_port_id]).igmp_wrong_ver_query = 0;
}


// This function is invoked to process a change in IGMP's global version
// Changing the global version affects the version of all ports that are not explicitly
// configured. So, update the oper_version of all such ports.

void igmp_set_global_version (VRF_INDEX  vrf_index, 
        UINT32     version, 
        BOOL       force)
{
    MCGRP_CLASS       *igmp= IGMP_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    IP_PORT_DB_ENTRY  *portP;
    MCGRP_L3IF        *igmp_vport;

    // When we reset the IGMP global version, the change needs to trickle
    // down to all ports that do not have an explicitly configured version.

    if (!force && igmp->cfg_version == version)
        return;

    igmp->cfg_version = (UINT8) version;
    if (igmp->cfg_version == IGMP_VERSION_NONE)
        igmp->oper_version = IGMP_VERSION_DEFAULT;
    else
        igmp->oper_version = igmp->cfg_version;

    if (! igmp->enabled)
        return;

    // Walk thru all ports updating the port version for non-configured ports
    for (portP = IP_PORT_DB_HEAD; portP != NULL; IP_PORT_DB_NEXT(portP))
    {
        igmp_vport = gIgmp.port_list[portP->port_number];

        // If the port does not exist or is part of a virtual port
        // or has a version explicitly configured, skip it.
        // The reason why we skip virtual port members is that they are taken care of later
        if (igmp_vport == NULL ||
                (!force && (igmp_vport->cfg_version != IGMP_VERSION_NONE)) )
        {
            continue;
        }

        // Update this port's 
        igmp_vport->oper_version = igmp->oper_version;
        if (force)
            igmp_vport->cfg_version = igmp->cfg_version;

        // and if this is a virtual port, update its member ports too.
        if (MCGRP_IS_PORT_VIRTUAL(igmp_vport))
        {
            igmp_update_ve_member_ports(igmp, igmp_vport, (UINT8)igmp_vport->oper_version, 
                    force);
        }
        else
        {
            if (igmp_vport->phy_port_list)
            { 
                igmp_vport->phy_port_list->oper_version = igmp_vport->oper_version;
                //      (igmp->igmp_stats[igmp_vport->phy_port_id]).igmp_wrong_ver_query = 0;
                (igmp->igmp_stats[igmp_vport->vir_port_id]).igmp_wrong_ver_query = 0;
            }
        }
    }
} /* igmp_set_global_version() */


// This function is invoked to process a change in an interface's (VE or otherwise) version
int igmp_set_if_igmp_version (VRF_INDEX  vrf_index, 
        UINT16     vport, 
        UINT8      version)
{
    MCGRP_CLASS  *igmp = IGMP_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
    MCGRP_L3IF   *igmp_vport;

    if (!MCGRP_IS_VALID_INTF(vport))
    {
        return -1;
    }

    igmp_vport = gIgmp.port_list[vport];
    if (igmp_vport == NULL)
    {
        igmp_vport = mcgrp_alloc_init_l3if_entry(igmp, vport);
        if (!igmp_vport)
            return -1;
        igmp_vport->is_up = FALSE;
    }
    else
    {
        if (igmp_vport->cfg_version == version)
            return 0;
    }

    L2MCD_LOG_DEBUG("%s(%d) vport:%d version:%d Prev vport->cfg_version:%d ", __FUNCTION__, __LINE__,
            vport, version, igmp_vport->cfg_version);
    igmp_vport->cfg_version  = version;
    igmp_vport->oper_version = (igmp_vport->cfg_version == IGMP_VERSION_NONE) ?
        igmp->oper_version : igmp_vport->cfg_version;

    // Update the version for this VE's member ports if this is a virtual port
    if (MCGRP_IS_PORT_VIRTUAL(igmp_vport))
    {
        igmp_update_ve_member_ports(igmp, igmp_vport, (UINT8) igmp_vport->oper_version,
                FALSE /* do not force */);
    }
    else
    { 
        if (igmp_vport->phy_port_list)
        {
            igmp_vport->phy_port_list->oper_version = igmp_vport->oper_version;
            (igmp->igmp_stats[igmp_vport->vir_port_id]).igmp_wrong_ver_query = 0;
            L2MCD_LOG_DEBUG("%s(%d) phy_port:%d oper_version:%d ", __FUNCTION__, __LINE__, 
                    igmp_vport->phy_port_list->phy_port_id, igmp_vport->phy_port_list->oper_version);
        }
    }
    mcgrp_handle_intf_ver_change(igmp, igmp_vport);
    return 0;
}

