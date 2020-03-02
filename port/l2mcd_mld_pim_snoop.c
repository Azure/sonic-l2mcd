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

#include "l2mcd_mld_port.h"


extern MCGRP_CLASS *g_igmp_destroy;
extern MCGRP_CLASS *g_mld_destroy;

/*	When we receive (*,G) join/prune on a port then here
 *  we according send add/del this port for all (S,G)s in this grp to mcastss
 */
void  l2mcd_sync_pims_upd_inherit_ports_to_sg(MCGRP_ENTRY *mcgrp_entry, 
										MCGRP_MBRSHP *rcvd_mbrshp,
										uint32_t vid, uint32_t phy_ifindex, 
										UINT8 afi, UINT8 add,UINT32 ivid)
{
	MCGRP_MBRSHP *mbrshp = NULL, *next_mbrshp = NULL;
	MCGRP_SOURCE  *mcgrp_src = NULL, *next_src = NULL;
	int rc = 0;
	if(!mcgrp_entry || !rcvd_mbrshp) {
		MLD_LOG(MLD_LOGLEVEL9, afi, "%s(%d) PIMS: input is NULL ", FN, LN);
		return;
	}

	mbrshp = mcgrp_find_first_mbrshp(mcgrp_entry);
	while (mbrshp) {
		next_mbrshp = mcgrp_find_next_mbrshp(mcgrp_entry, mbrshp);
		mcgrp_src = mbrshp->pims_src_list;
		if(rcvd_mbrshp == mbrshp) {
			MLD_LOG(MLD_LOGLEVEL9, afi,
				"%s(%d) Skip inherit, Received port%d is part of the membership %d (%s)..", 
				FN, LN, rcvd_mbrshp->phy_port_id, mbrshp->phy_port_id,
				mld_get_if_name_from_ifindex(mbrshp->phy_port_id));
			mbrshp = next_mbrshp;
			continue;
		}
		
		while (mcgrp_src)
		{
			next_src = mcgrp_src->next;
			/*
		 	 * add==1 : get each source and send port add for that SG to mcastss
			 * add==0 : get each source and send port del for that SG to mcastss
		 	 */
			if(add) {
					MLD_LOG(MLD_LOGLEVEL5, afi,
						"%s(%d):PIMS: send [%s, %s] inherit %s to McastSS ifindex:0x%x ", 
						FN, LN,
						mcast_print_addr(&mcgrp_src->src_addr), 
						mcast_print_addr(&mcgrp_entry->group_address), 
						"Add", phy_ifindex);
				}
			else {
				if(!mld_snp_is_source_present_on_mbr_port(rcvd_mbrshp, mcgrp_src->src_addr.ip.v4addr, afi))
				{
					MLD_LOG(MLD_LOGLEVEL5, afi,
						"%s(%d):PIMS: send [%s, %s] inherit %s to McastSS ifindex:0x%x ", 
						FN, LN,
						mcast_print_addr(&mcgrp_src->src_addr), 
						mcast_print_addr(&mcgrp_entry->group_address), 
						"Delete", phy_ifindex);
				}else {
					MLD_LOG(MLD_LOGLEVEL6, afi,
						"%s(%d) PIMS: src %s is part of recv_mbrshp skip delete to mcastss ", FN, LN,
						mcast_print_addr(&mcgrp_src->src_addr));
				}

			}
			if(rc)
				L2MCD_LOG_INFO("%s(%d): update to McastSS failed. [%s, %s], vid:%d, add:%d, ifindex:0%x",
					__FUNCTION__, __LINE__, mcast_print_addr(&mcgrp_src->src_addr),
					mcast_print_addr(&mcgrp_entry->group_address), vid, add, phy_ifindex);
			mcgrp_src = next_src;
		}
		mbrshp = next_mbrshp;
	}	
	return;
}

BOOLEAN pim_snoop_is_source_present_on_mbr_port(MCGRP_MBRSHP *grp_mbrshp, 
						uint32_t src_addr, uint8_t afi)
{
	MCGRP_SOURCE *src_entry = NULL, *next_entry = NULL;

	if(!grp_mbrshp || (src_addr == 0))
		return FALSE;
		
	src_entry = grp_mbrshp->pims_src_list;
	while (src_entry) {
		next_entry  = src_entry->next;
		if(src_entry->src_addr.ip.v4addr == src_addr)
			return TRUE;
		src_entry = next_entry;
	}
	
	return FALSE;
}

/* This function will include/exclude the current physical port and exclude any other port where S,G RptPrune is received
   for this source. The function adds all ports where IGMP/PIMS *,G joins are received. These are sent 
   as (S,G) add/delete to mcastss. The last parameter indicates add/delete option. */
void l2mcd_sync_inherit_and_send_rte(MCGRP_CLASS  *mcgrp, MCGRP_L3IF *mcgrp_vport, 
									   MCGRP_ENTRY *mcgrp_entry, UINT32 phy_port_id, MADDR_ST *src_addr, int add_flag)
{
	MCGRP_MBRSHP *mbrshp = NULL, *next_mbrshp = NULL;
	MCGRP_MBRSHP *rcvd_mbrshp = NULL;
	uint32_t    *send_ifs;
	int count = 0, i = 0;
	MCGRP_SOURCE* pims_src_entry;
	uint8_t v1_mbr = 0, v2_mbr = 0, v3_mbr = 0;
	uint8_t include_flag = 0, exclude_flag = 0;
	rcvd_mbrshp = mcgrp_find_mbrshp_entry(mcgrp_entry, phy_port_id);
	mld_snp_is_igmpv3_source_present_on_mbr_port(rcvd_mbrshp, src_addr->ip.v4addr,
						mcgrp_entry->group_address.afi, &include_flag, &exclude_flag);
	//FIRST Iteration to calculate count to allocate send_ifs payload.
	mbrshp = (MCGRP_MBRSHP *) M_AVLL_FIRST(mcgrp_entry->mbr_ports_tree);
	for (;mbrshp; mbrshp = next_mbrshp)
	{
		v1_mbr = 0; v2_mbr = 0; v3_mbr = 0;
		next_mbrshp = (MCGRP_MBRSHP *)M_AVLL_NEXT(mcgrp_entry->mbr_ports_tree,
			mbrshp->node);

		/* If we received a (S,G) RptPrune on this port, exclude this port*/
		pims_src_entry = (MCGRP_SOURCE*) mcgrp_pims_find_src_node_by_addr(mcgrp, 
													mbrshp, src_addr);
		if (pims_src_entry && pims_src_entry->rpt_flag == 1) {
			MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV4_AFI, 
				"%s(%d) src_entry has rpt_flag set. skipping [%s, %s] ", 
				FN, LN, mcast_print_addr(src_addr), mcast_print_addr(&mcgrp_entry->group_address));
			continue;
		}
		mld_is_snoop_mbrship_present(mbrshp, &v1_mbr, &v2_mbr, &v3_mbr);
		if((mbrshp->pims_mbr_flags & PIMS_WG_MBR_PORT) || v2_mbr)
			count++;
	}
	/* If this source is present in IGMPv3 source list on this port
	 *  then we should not send to add/delete. ADD is redundant 
	 * DEL should not be sent since v3 source is present on this port.
	 */
	if(!include_flag)
		count++;
	send_ifs = dy_malloc(count * sizeof(uint32_t));
	if(!send_ifs)
		return; 
	
	mbrshp = (MCGRP_MBRSHP *) M_AVLL_FIRST(mcgrp_entry->mbr_ports_tree);
	for (;mbrshp; mbrshp = next_mbrshp)
	{
		v1_mbr = 0; v2_mbr = 0; v3_mbr = 0;
		next_mbrshp = (MCGRP_MBRSHP *)M_AVLL_NEXT(mcgrp_entry->mbr_ports_tree,
			mbrshp->node);

		/* If we received a (S,G) RptPrune on this port, exclude this port*/
		pims_src_entry = (MCGRP_SOURCE*) mcgrp_pims_find_src_node_by_addr(mcgrp, 
													mbrshp, src_addr);
		if(pims_src_entry && pims_src_entry->rpt_flag == 1) {
			MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI,
					"%s(%d) skip as source rpt_flag true ", FN, LN);
			continue;
		}
		MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, 
				"%s(%d) [%s, %s] pims_mbr_flags:0x%x ifindex:0x%x (%s) ", FN, LN, 
				mcast_print_addr(src_addr), mcast_print_addr(&mcgrp_entry->group_address), 
				mbrshp->pims_mbr_flags, mld_get_port_ifindex(mbrshp->phy_port_id),
				mld_get_if_name_from_ifindex(mbrshp->phy_port_id));
		/* Inherit only IGMPv2 (*,G) member ports to SG
		 */
    	mld_is_snoop_mbrship_present(mbrshp, &v1_mbr, &v2_mbr, &v3_mbr);
		if((mbrshp->pims_mbr_flags & PIMS_WG_MBR_PORT) || v2_mbr)
			send_ifs[i++] = mbrshp->phy_port_id;
	}
	
	if(!include_flag)
		send_ifs[i] = phy_port_id;

	MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV4_AFI, 
			"%s(%d) Send [%s, %s] %s count:%d phy_port:%s Rte to McastSS ", FN, LN, 
			mcast_print_addr(src_addr), 
			mcast_print_addr(&mcgrp_entry->group_address), 
			add_flag ? "Add" : "Delete", count, mld_get_if_name_from_ifindex(phy_port_id));
	
	dy_free(send_ifs);	
	return;
}

BOOLEAN pims_is_pim_snoop_mbrship(MCGRP_MBRSHP *mcgrp_mbrshp)
{
	if(!mcgrp_mbrshp)
		return FALSE;
		
	if((mcgrp_mbrshp->pims_mbr_flags & PIMS_WG_MBR_PORT) ||
		(mcgrp_mbrshp->pims_mbr_flags & PIMS_SG_MBR_PORT))
		return TRUE;
	
	return FALSE;
}

void mcgrp_pims_age_src_mbrshp(MCGRP_CLASS  *mcgrp,
						MCGRP_L3IF *mcgrp_vport,
						MCGRP_ENTRY *mcgrp_entry,
						MCGRP_MBRSHP *mcgrp_mbrshp,
						MCGRP_SOURCE *pims_src_entry)
{
	MCGRP_GLOBAL_CLASS   *mcgrp_glb = NULL;
	MADDR_ST			 src_addr; 
	
	if (!mcgrp_vport || !mcgrp_entry ||
		!mcgrp_mbrshp || !pims_src_entry)
	{
		L2MCD_LOG_INFO("%s(): Invalid arg passed", __FUNCTION__);
		return;
	}

	mcgrp_glb = IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld;

	if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&pims_src_entry->pims_src_tmr.mcgrp_wte))
		WheelTimer_DelElement(mcgrp->mcgrp_wtid, &pims_src_entry->pims_src_tmr.mcgrp_wte);

	/* delete the src node */
	
	src_addr.afi = pims_src_entry->src_addr.afi;
	mcast_set_addr_any(&src_addr);
	mcast_set_addr(&src_addr, &pims_src_entry->src_addr);

	mcgrp_pims_sorted_linklist_del_element(mcgrp_glb, mcgrp, mcgrp_mbrshp, &pims_src_entry->src_addr);
	mcgrp_vport->pims_num_sg_entries--;
			
	MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, 
			"%s(%d)  src:%s aged on port:%d, send update to McastSS", FN, LN,
			mcast_print_addr(&src_addr), mcgrp_mbrshp->phy_port_id);

	/* (S,G) port delete, update to mcastss */ 
	l2mcd_sync_inherit_and_send_rte(mcgrp, mcgrp_vport, mcgrp_entry, 
						 mcgrp_mbrshp->phy_port_id, &src_addr, 0);
	
	MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, "%s(%d) remaining sg_entries:%d ", 
		FN, LN, mcgrp_vport->pims_num_sg_entries);
	
	L2MCD_LOG_INFO("%s(%d) remaining sg_entries:%d ", FN, LN, mcgrp_vport->pims_num_sg_entries);
	
	if(!mcgrp_mbrshp->pims_src_list)
	{
		if(!(mcgrp_mbrshp->pims_mbr_flags & PIMS_WG_MBR_PORT) && 
			!(mcgrp_mbrshp->pims_mbr_flags & MLD_OR_IGMP_JOIN_PORT))
		{
			mcgrp_notify_phy_port_del(mcgrp, &mcgrp_entry->group_address, mcgrp_vport, 
		                          mcgrp_mbrshp->phy_port_id, TRUE);
			mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mcgrp_mbrshp);
			mcgrp_entry->pims_num_sg_join_ports--;
		
			/* If there are no members left in this group, delete the group too */
			if(!mcgrp_entry->pims_num_wg_join_ports && !mcgrp_entry->pims_num_sg_join_ports)
			{
				if (mcgrp_entry->num_mbr_ports == 0)    /* No member ports */
				{
					MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI,
							"%s(%d)PIMS destroy group %s entry ", FN, LN,
							mcast_print_addr(&mcgrp_entry->group_address));
					mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, mcgrp_entry);
				}
			}
		}
		else
		{
			if(mcgrp_mbrshp->pims_mbr_flags & PIMS_SG_MBR_PORT)
			{
				mcgrp_mbrshp->pims_mbr_flags &= ~PIMS_SG_MBR_PORT;
				mcgrp_entry->pims_num_sg_join_ports--;
			}
		}
	}

	return;
}

MCGRP_SOURCE* mcgrp_pims_find_src_node_by_addr (MCGRP_CLASS  *mcgrp,
											MCGRP_MBRSHP *mcgrp_mbrshp,
											MADDR_ST *src_addr)
{
	MCGRP_GLOBAL_CLASS   *mcgrp_glb = NULL;
	MCGRP_SOURCE *entry = NULL;
	SORTED_LINKLIST_KEYINFO *keyinfo;
	if(!mcgrp || !mcgrp_mbrshp || !src_addr)
		return NULL;

	mcgrp_glb = IS_IGMP_CLASS(mcgrp) ? &gIgmp : &gMld;
	keyinfo = mcgrp_glb->mcgrp_src_keyinfo;
	entry = mcgrp_mbrshp->pims_src_list;
	for(; entry; entry = entry->next)
	{
		if(keyinfo->key_compare(&entry->src_addr, src_addr) == 0)	
			return entry;	
	}

	return NULL;
}

void mcgrp_pims_sorted_linklist_del_element(MCGRP_GLOBAL_CLASS *mcgrp_glb,
								MCGRP_CLASS  *mcgrp, MCGRP_MBRSHP *mcgrp_mbrshp,
								MADDR_ST *src_addr)
{
	if(!mcgrp_glb || !mcgrp || !mcgrp_mbrshp) {
		L2MCD_LOG_INFO("%s: NULL parameter", __FUNCTION__);
		return;
	}

	if (IS_IGMP_CLASS(mcgrp))
		g_igmp_destroy = mcgrp;
	else
		g_mld_destroy = mcgrp;

	sorted_linklist_del_one_item(mcgrp_glb->src_specific_pool,
			mcgrp_glb->mcgrp_src_keyinfo,
			(SORTED_LINKLIST**)&mcgrp_mbrshp->pims_src_list, src_addr);

	return;

}


