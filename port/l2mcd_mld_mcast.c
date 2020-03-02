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

#include "l2mcd_mld_utils.h"
#include "mld_vlan_db.h"

extern void 
l2mcd_sync_pims_upd_inherit_ports_to_sg(MCGRP_ENTRY *mcgrp_entry, 
										MCGRP_MBRSHP *rcvd_mbrshp,
										uint32_t vid, uint32_t phy_ifindex, 
										UINT8 afi, UINT8 add,UINT32 ivid);
bool_t received_clear_grp_notify = FALSE;

void mld_send_l2mcd_sync_group_upd (MADDR_ST *group_address,  UINT16 vir_port_id, 
	int num_add_port, UINT32 add_phy_port_id, int num_del_port, UINT32 del_phy_port_id,
	MADDR_ST  *src_addr, uint8_t is_remote_report)
{
	uint32_t vid = 0,gvid = 0;
	uint32_t phy_ifindex = (num_add_port ? add_phy_port_id : del_phy_port_id);
	uint32_t ifindex = mld_get_port_ifindex (vir_port_id);
	int      add = (num_add_port ? TRUE : FALSE);
	MCGRP_ENTRY *mcgrp_entry = NULL;
	MCGRP_CLASS	*mcgrp = NULL;
	MCGRP_MBRSHP *mcgrp_mbrshp = NULL;
	MADDR_ST source_address;

	/* Notify mcastss only for non-router ports */
	if ((received_clear_grp_notify) || (l2mcd_ifindex_is_physical(ifindex))) 
	    return;
    
	if (group_address == NULL || src_addr == NULL)
	{
		L2MCD_LOG_INFO("%s(%d)  Input is NULL grp:%s ", __FUNCTION__, __LINE__ ,
			group_address ? mcast_print_addr(group_address) : " ");
		return;
	}

	vid = mld_get_ivid_vport (vir_port_id,group_address->afi);
	gvid = mld_get_vlan_id (vir_port_id);

	source_address.afi = group_address->afi;
	mcast_set_addr_any (&source_address);

	mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(group_address->afi, MLD_DEFAULT_VRF_ID);
	mcgrp_entry = mcgrp_find_group_address_entry (mcgrp, vir_port_id, group_address);

	if (!mcgrp_entry)
		return;

	l2mcd_system_group_entry_notify(group_address, src_addr, vid, phy_ifindex, FALSE, add);
	if (mcgrp_entry->pims_num_sg_join_ports > 0)		
	{
		/*PIMS snooping remove the port from all SG since it got inherited */
		//(*,G) case
		if (src_addr && mcast_addr_any (src_addr))
		{
			mcgrp_mbrshp = mcgrp_find_mbrshp_entry (mcgrp_entry, phy_ifindex);
			if (mcgrp_mbrshp != NULL) {
				l2mcd_sync_pims_upd_inherit_ports_to_sg (mcgrp_entry, mcgrp_mbrshp, gvid, phy_ifindex,
					mcgrp_entry->group_address.afi, add, vid);
			}
    	}
    }
	if (src_addr && mcast_addr_any (src_addr))
		l2mcd_sync_inherit_xg_port_to_all_sg (mcgrp_entry, phy_ifindex, vid, add);
}

void mld_send_l2mcd_sync_group_clr (UINT16 ivid, BOOLEAN isGlobalClear, uint8_t afi)
{	
    unsigned char flag = 0;

    if (isGlobalClear) flag |= L2MCD_SYNC_IGMP_SNP_GLB_CLR;
}

void mld_send_l2mcd_sync_group_add (MADDR_ST *group_address, UINT16 vir_port_id,
        UINT32 phy_port_id, MADDR_ST  *src_addr, UINT8  filter_mode) 
{
    uint32_t      vid,gvid, phy_ifindex = phy_port_id;;
    MCGRP_ENTRY  *mcgrp_entry = NULL;
    MCGRP_CLASS  *mcgrp = NULL;
    MCGRP_MBRSHP *mcgrp_mbrshp = NULL;
    MADDR_ST      source_address;

    source_address.afi = group_address->afi;
    mcast_set_addr_any (&source_address);
    gvid=vir_port_id;
	vid=vir_port_id;
    mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(group_address->afi, MLD_DEFAULT_VRF_ID);
    mcgrp_entry = mcgrp_find_group_address_entry (mcgrp, vir_port_id, group_address);

    if (!mcgrp_entry)
        return;
    l2mcd_system_group_entry_notify(&mcgrp_entry->group_address, &source_address, vir_port_id, phy_port_id, 0, 1);

    /* PIMS inherit this port to all SG routes */
    if (mcgrp_entry->pims_num_sg_join_ports > 0)
    {
        mcgrp_mbrshp = mcgrp_find_mbrshp_entry (mcgrp_entry, phy_port_id);

        if (mcgrp_mbrshp != NULL)
            l2mcd_sync_pims_upd_inherit_ports_to_sg (mcgrp_entry, mcgrp_mbrshp, 
                    gvid, phy_ifindex, mcgrp_entry->group_address.afi, TRUE,vid);
    }

    /* Inherit (X,G) ports to the newly added (S,G) entry */
    l2mcd_sync_inherit_xg_port_to_all_sg (mcgrp_entry, phy_ifindex, vid, TRUE);
}

void igmpv3_send_l2mcd_sync_group_upd (MADDR_ST *group_address, UINT16 vir_port_id, 
	int num_add_port, UINT32 add_phy_port_id, int num_del_port, UINT32 del_phy_port_id,
	MADDR_ST  *src_addr, uint8_t is_remote_report, UINT8  filter_mode)
{
	uint32_t     vid = mld_get_ivid_vport (vir_port_id, group_address->afi);
	uint32_t     ifindex = mld_get_port_ifindex (vir_port_id);
	uint32_t     phy_ifindex = (num_add_port ? add_phy_port_id : del_phy_port_id);
	int          add = (num_add_port ? TRUE : FALSE);
	MCGRP_ENTRY *mcgrp_entry = NULL;
	MCGRP_CLASS	*mcgrp = NULL;
	
    /* Notify mcastss only for non-router ports */
	if ((received_clear_grp_notify) || (l2mcd_ifindex_is_physical(ifindex)))
	{
		L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] ifindex:0x%x num_add_port:%d ", __FUNCTION__, __LINE__, vid, ifindex,num_add_port);
		return;
	}

	if (num_del_port) {
		l2mcd_system_group_entry_notify(group_address, src_addr, vid, phy_ifindex, 0, 0);
	} else if (num_add_port) {
		l2mcd_system_group_entry_notify(group_address, src_addr, vid, phy_ifindex, 0, 1);
	}
	
	mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(group_address->afi, MLD_DEFAULT_VRF_ID);
	mcgrp_entry = mcgrp_find_group_address_entry (mcgrp, vir_port_id, group_address);

	if (!mcgrp_entry) return;

	l2mcd_sync_inherit_xg_ports_to_this_sg (mcgrp_entry, src_addr, filter_mode, vid, add);
}

void igmpv3_send_l2mcd_sync_group_add (MADDR_ST *group_address, UINT16 vir_port_id,
	UINT32 phy_port_id, MADDR_ST  *src_addr, UINT8  filter_mode)
{
	MCGRP_ENTRY *mcgrp_entry = NULL;
	MCGRP_CLASS	*mcgrp       = NULL;
	uint32_t     vid, phy_ifindex = phy_port_id;
	
	vid = mld_get_ivid_vport (vir_port_id,group_address->afi);
    L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] vir_port_id:%d, phy_ifindex:%d", __FUNCTION__, __LINE__, vid, vir_port_id, phy_ifindex);
    l2mcd_system_group_entry_notify(group_address, src_addr, vid, phy_ifindex, 0, 1);

	mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(group_address->afi, MLD_DEFAULT_VRF_ID);
	mcgrp_entry = mcgrp_find_group_address_entry(mcgrp, vir_port_id, group_address);

	if (!mcgrp_entry)
	{
		L2MCD_VLAN_LOG_ERR(vid, "%s:%d vid:%d vir_port_id:%d", __FUNCTION__, __LINE__, vid, vir_port_id);
		return;
	}
	l2mcd_sync_inherit_xg_ports_to_this_sg (mcgrp_entry, src_addr, filter_mode, vid, TRUE);
}

void l2mcd_sync_inherit_xg_port_to_all_sg (MCGRP_ENTRY *mcgrp_entry, uint32_t phy_ifindex, uint32_t vid, int add)
{
    MCGRP_MBRSHP *mbrshp = (MCGRP_MBRSHP *) M_AVLL_FIRST(mcgrp_entry->mbr_ports_tree);
    MCGRP_SOURCE *src = NULL;
    int           i = 0;

    L2MCD_VLAN_LOG_DEBUG(vid, "%s:%d:[vlan:%d] GRP:%x Phy:%x VID:%d Add:%d", __FUNCTION__, __LINE__,vid,
            mcgrp_entry->group_address.ip.v4addr, phy_ifindex, vid, add);

    /* Loop through all the member ports of the Group entry (for both INCLUDE & EXCLUDE List,
     * and the new (X,G) member to all of the existing (S,G) entries */
    for (; mbrshp; mbrshp = (MCGRP_MBRSHP *) M_AVLL_NEXT(mcgrp_entry->mbr_ports_tree, mbrshp->node))
    {
        if (mbrshp->phy_port_id == phy_ifindex)
            continue;

        for (i = FILT_INCL; i <= FILT_EXCL; i++)
        {
            for (src = mbrshp->src_list[i]; src; src = src->next)
            {
                L2MCD_VLAN_LOG_DEBUG(vid,"%s:%d:[vlan:%d] GRP:%x Src:%x Port:%x", __FUNCTION__, __LINE__,vid,
                        mcgrp_entry->group_address.ip.v4addr, src->src_addr.ip.v4addr, mbrshp->phy_port_id);

                /* Check if its (S,G) entry, then add the new (X,G) member to that (S,G) entry */
                if (src->src_addr.afi != 0 && mcast_is_valid_unicast (&src->src_addr))
                {

                    l2mcd_system_group_entry_notify(&mcgrp_entry->group_address, &(src->src_addr), vid, phy_ifindex, 0, add);
                }
            }
        }
    }
}

void l2mcd_sync_inherit_xg_ports_to_this_sg (MCGRP_ENTRY *mcgrp_entry, MADDR_ST *src_addr, UINT8 filter_mode, uint32_t vid, int add)
{
	MCGRP_MBRSHP *mbrshp = NULL;
	int           member_cnt = 0;

	/* This function handling only for (S,G) entry member add.
	 * If the first member is added to this (S,G) entry, then add all (*,G) members to this new (S,G) entry.
	 * If the last member is deleted from the (S,G) entry, then delete all (*,G) members inherited in the (S,G) entry */
	if (src_addr->afi == 0 || (!mcast_is_valid_unicast (src_addr))) {
		L2MCD_LOG_INFO("%s %d GRP:%x SRC:%x AFI:%d", __FUNCTION__, __LINE__,
			mcgrp_entry->group_address.ip.v4addr, src_addr->ip.v4addr, src_addr->afi);
		return;
	}

	/* Find how many ports are member of this source */
	for (mbrshp = (MCGRP_MBRSHP *) M_AVLL_FIRST(mcgrp_entry->mbr_ports_tree); mbrshp;
		mbrshp = (MCGRP_MBRSHP *) M_AVLL_NEXT(mcgrp_entry->mbr_ports_tree, mbrshp->node))
	{
		if (mcgrp_find_source (mbrshp, src_addr, filter_mode))
			member_cnt++;
	}

	L2MCD_LOG_INFO("%s %d GRP:%x CNT:%d Filt:%d Add:%d", __FUNCTION__, __LINE__,
		mcgrp_entry->group_address.ip.v4addr, member_cnt, filter_mode, add);

	if (add) {
		/* In ADD, if there is zero or more than one member in that (S,G) entry, do nothing */
		if (member_cnt != 1) return;
	} else {
		/* In Del, if there is one or more member in that (S,G) entry, do nothing */
		if (member_cnt != 0) return;
	}

	/* Loop through all the member ports of the group entry, If that port is member of the (*,G) entry,
	 * add/delete that port into the created/deleted (S,G) entry */
	for (mbrshp = (MCGRP_MBRSHP *) M_AVLL_FIRST(mcgrp_entry->mbr_ports_tree); mbrshp;
		mbrshp = (MCGRP_MBRSHP *) M_AVLL_NEXT(mcgrp_entry->mbr_ports_tree, mbrshp->node))
	{
		if ((mbrshp->src_list[FILT_INCL] == NULL) && (mbrshp->src_list[FILT_EXCL] == NULL))
		{
			L2MCD_LOG_INFO("%s %d GRP:%x ADD:%d Port:%x", __FUNCTION__, __LINE__,
				mcgrp_entry->group_address.ip.v4addr, add, mbrshp->phy_port_id);

            l2mcd_system_group_entry_notify(&mcgrp_entry->group_address, src_addr, vid, mbrshp->phy_port_id, 0, add);
		}
	}
}
