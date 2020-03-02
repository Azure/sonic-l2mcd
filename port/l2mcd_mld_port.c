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
#include "l2mcd_portdb.h"
#include "l2mcd_dbsync.h"
#include <time.h>

L2MCD_AVL_TREE *mld_portdb_tree = &gMld.portdb_tree;
L2MCD_AVL_TREE *ve_mld_portdb_tree = &gMld.ve_portdb_tree;
L2MCD_AVL_TREE *l3_portdb_tree = &gMld.portdb_tree;
extern bool_t received_clear_grp_notify;
extern struct list *snooping_enabled_vlans[MCAST_AFI_MAX];

extern void mcgrp_pims_destroy_src_list(MCGRP_CLASS *mcgrp,
        MCGRP_MBRSHP *mcgrp_mbrshp);


uint32_t pim_get_ifindex_from_port(int port)
{
    return (IP_IP_PORT(port).config.ifindex);

}

/* MLDS Set Query Interval */		
int 
mld_query_interval_set(uint32_t afi, uint32_t vid, uint32_t query_interval , uint8_t type)
{
	int ret = MLD_SUCCESS;
	mld_vlan_node_t *vlan_node = NULL;
	mld_cfg_param_t *cfg;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_LOG_NOTICE("%s vid is not available %d",
				       __FUNCTION__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

	cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, afi);
	if (!cfg) {
        L2MCD_LOG_NOTICE("%s %d malloc error", __FUNCTION__, __LINE__);
        return MLD_CLI_ERR_NO_SUCH_IFF;
    }

    if (query_interval <=  cfg->max_response_time){
        L2MCD_LOG_NOTICE("Error : %s(): query interval time is lesser than equal to query response"
                "time QI = %d , current res = %d", __FUNCTION__, query_interval, cfg->max_response_time);
        return  MLD_CLI_ERR_QI_LE_QRI;
    }



	cfg->cfg_query_interval_time = query_interval;

    if (!mld_is_flag_set(vlan_node, afi, MLD_START_UP_QUERY_INTERVAL))
	{
        cfg->start_up_query_interval = query_interval/4;
	}

	if (vlan_node->ivid
	    && mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
		ret =
		    mld_proto_query_interval_set(afi, vlan_node->ivid,
						 vlan_node->gvid,
						 query_interval,
                         vlan_node->type);

	return (ret);
}

/*MLD Snooping Query Max Response Time Set*/
int
mld_query_max_response_time_set(uint32_t afi, uint32_t vid, uint32_t qmrt, uint8_t type)
{
	int ret = MLD_SUCCESS;
	mld_vlan_node_t *vlan_node  = NULL;
	mld_cfg_param_t *cfg;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_LOG_NOTICE("%s vid is not available %d",
				       __FUNCTION__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

	cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, afi);
	if (!cfg) {
		L2MCD_LOG_NOTICE("%s %d malloc error", __FUNCTION__, __LINE__);
		return MLD_CLI_ERR_NO_SUCH_IFF;
		goto EXIT;
	}
  
    cfg->max_response_time = qmrt;
	if (vlan_node->ivid
	    && mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
		ret = mld_proto_query_max_response_time_set(afi, vlan_node->ivid,
						      qmrt, vlan_node->type);
	else
		L2MCD_LOG_NOTICE("%s %d %d %d", __FUNCTION__, __LINE__, vid,
			       vlan_node->ivid);

      EXIT:
	return (ret);
}

/*Last Member Query Interval value set*/
int
mld_lmqi_set(uint32_t afi, uint32_t vid, uint32_t lmqi, uint8_t type)
{
    	int ret = 0;
	mld_vlan_node_t *vlan_node  = NULL;
	mld_cfg_param_t *cfg;
   
	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_LOG_NOTICE("%s vid is not available %d",
				       __FUNCTION__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

	cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, afi);
	if (!cfg) {
		L2MCD_LOG_NOTICE("%s %d malloc error", __FUNCTION__, __LINE__);
		return MLD_CLI_ERR_NO_SUCH_IFF;
		goto EXIT;
	}

	cfg->LMQ_interval = lmqi; /* Store in Milli Seconds */

	if (vlan_node->ivid
			&& mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
		mld_proto_lmqi_set(afi, vlan_node->ivid,  lmqi, vlan_node->type);
	else
		L2MCD_LOG_NOTICE("%s %d %d %d", __FUNCTION__, __LINE__, vid,
				vlan_node->ivid);

      EXIT:
	return (ret);
}

int mld_if_set_version_api(int vrf_index, uint32_t vid, int version, int afi,uint8_t type)
{
	int port = 0;	
	MCGRP_L3IF *mcgrp_vport = NULL;
	MCGRP_CLASS *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, MLD_DEFAULT_VRF_ID);
	mld_vlan_node_t *vlan_node = NULL;
	mld_l2_static_group_t *static_grp;
	MADDR_ST grp_addr;
	mld_l3_if_type_t if_type;
	struct list *s_list;
	struct listnode *list_node;
	uint32_t pport;
	char str[46];
    mld_cfg_param_t *cfg;
    MCGRP_PORT_ENTRY *mcgrp_pport = NULL;

	vlan_node = mld_vdb_vlan_get(vid,type);
	if(vlan_node == NULL)
	{
		L2MCD_LOG_INFO("%s(%d) vid:%x vlan_node is NULL. ", FN, LN, vid);
		return -1; 
    }

    cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, afi);
    if (!cfg) {
        L2MCD_LOG_INFO("%s %d malloc error", __FUNCTION__, __LINE__);
        return MLD_CLI_ERR_NO_SUCH_IFF;
    }
	port = mld_l3_get_port_from_ifindex(vlan_node->ifindex,vlan_node->type);
	L2MCD_VLAN_LOG_DEBUG(vid,"%s:%d:[vlan:%d version:%d old_ver:%d port:%d ", 
						FN, LN, vid, version, vlan_node->cfg_version, port);

    if (afi == MLD_IP_IPV4_AFI) {
        if(((cfg->cfg_version == IGMP_VERSION_2) && (version == IGMP_VERSION_3)) ||
                ((cfg->cfg_version == IGMP_VERSION_3) && (version == IGMP_VERSION_2))) {
            /* If there is a config version change for a vlan, then clear the  
             *	snooping DB for that vlan.
             */
            mld_snoop_clear_on_version_change(vid, afi, type);
        }

        vlan_node->cfg_version = version;
        cfg->cfg_version = version; //assign this to l3if in case protocol enable/disable.
        igmp_set_if_igmp_version(vrf_index, port, version);
    }

    /* handle the case to set version for mld*/
    else if (afi == MLD_IP_IPV6_AFI){ //MLD

    }
    

	mcgrp_vport = (afi == MCAST_IPV4_AFI) ? gIgmp.port_list[port]: gMld.port_list[port];
    /* Send IGMP/MLD version change info to mcastss */

	if(mcgrp_vport) {
        L2MCD_LOG_INFO("%s(%d): vid:%x, vlan_node_ver:%d, vport_version:%d, afi:%d", FN, LN, vid, 
                vlan_node->cfg_version, mcgrp_vport->cfg_version, afi);
	
        mcgrp_pport = mcgrp_vport->phy_port_list;
        for (; mcgrp_pport; mcgrp_pport = mcgrp_pport->next)
            mcgrp_pport->oper_version = version;

		//Start querier
		mcgrp_start_igmp_querier(mcgrp, mcgrp_vport, afi, TRUE);
	}

    
    if (mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
     {
        L2MCD_LOG_INFO("%s PIM/Snooping enabled, continue updating L2 static groups : ivid %d", __FUNCTION__, vlan_node->ivid);
    }
    else{
        L2MCD_LOG_INFO("%s PIM/Snooping not enabled : ivid %d", __FUNCTION__, vlan_node->ivid);
        return 0;
    }

	/*
	 * Post changing version replay static group config
	 */
	if_type = mld_get_l3if_type (vlan_node->ifindex);
	/* Get static group list according to Vlan/Ve/Phy port */
	if (if_type == MLD_IFTYPE_L3PHY)
		s_list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, TRUE);
	else
		s_list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, FALSE);

	LIST_LOOP(s_list, static_grp, list_node) {
		L2MCD_LOG_INFO("%s %d %s %s", __FUNCTION__, vlan_node->ivid,
				mld_ntop(&static_grp->grp_addr, str),static_grp->ifname);
	    pport = mld_get_lif_ifindex_from_ifname(static_grp->ifname,vid,type);
		if (mld_is_port_member_of_vlan(vlan_node, pport)) {
			mcast_set_ip_addr(&grp_addr, &static_grp->grp_addr);
			mcgrp_notify_l2_staticGroup_change(afi,MLD_DEFAULT_VRF_ID,
						&grp_addr, port,pport, TRUE);
		}
	}
	return 0; 
}

int
mld_snooping_mrouter_if_set_api(int vid, int iftype, char *ifname,
				int enable, uint8_t afi, uint8_t type)
{
	ifindex_t ifindex = 0;
	mld_vlan_node_t *vlan_node = NULL;
	char if_name[INTERFACE_NAMSIZ];
	uint32_t port_num = 0;
	int ret=0;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		if (enable)
		{
			vlan_node = mld_vlan_create_fwd_ref(vid, type);
		}
		else
		{
            L2MCD_VLAN_LOG_INFO(vid,"%s:%d:[vlan:%d] enable: unset, returning  ", __FUNCTION__,__LINE__, vid);
			return (MLD_SUCCESS);
		}
		if (!vlan_node)
		{
            L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] vlan_node doesnot exists ", __FUNCTION__, __LINE__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

//	ifindex = mld_get_ifindex_by_ifname(ifname, iftype);

	mld_get_ifname(ifname, iftype, if_name);
	ifindex = mld_get_lif_ifindex_from_ifname(if_name,vid,type);
	L2MCD_LOG_INFO("%s %d %d %s %d", __FUNCTION__, vlan_node->ivid,
		       ifindex, if_name, enable);
	mld_add_static_mrtr_to_pending_list(vlan_node, if_name, enable, afi);

     port_num = ifindex;

	if (!mld_is_port_member_of_vlan(vlan_node, port_num))
	{
        L2MCD_VLAN_LOG_ERR(vid, "%s:%d:[vlan:%d] port:%d not member of vlan",__FUNCTION__, __LINE__, port_num,vid);
		return (MLD_SUCCESS);
	}

	if (mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
	{
		mld_proto_snooping_mrouter_if_set_api(vlan_node,
						      MLD_DEFAULT_VRF_ID,
						      port_num, enable,
						      afi);
        L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] proto_mrtr_set - port:%d ret:%d",
                __FUNCTION__, __LINE__, vid, port_num, ret);
	}

	return (MLD_SUCCESS);
}

/*MLD Static Group set function*/
int 
mld_static_group_source_set(uint32_t vid, char *ifname, int iftype,
			    mcast_grp_addr_t * gaddr, enum BOOLEAN insert_flag, BOOLEAN is_ve, uint8_t type)
{
	MCGRP_CLASS      *mcgrp = NULL;
	MADDR_ST         grp_addr;
    mld_vlan_node_t  *vlan_node = NULL;
	PORT_ID vport;
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	int sg_ret = 0;
	mld_l2_static_group_t	static_grp;	
	int ip_vx_afi = gaddr->afi;
	char if_name[INTERFACE_NAMSIZ];
	uint32_t port_num = 0;

	mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(ip_vx_afi, MLD_DEFAULT_VRF_ID);
	if (!mcgrp) {
		L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] mcgroup not exists vrf:%d afi:%d", FN, LN, vid,MLD_DEFAULT_VRF_ID,ip_vx_afi);
		return (-1);
    }

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] creation failed", FN, LN, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

	vport = mld_l3_get_port_from_ifindex(vlan_node->ifindex,vlan_node->type);

	mcast_set_ip_addr(&grp_addr, gaddr);
	if (!mcast_is_valid_grpaddr(&grp_addr)) {
		L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] %s",FN, LN, vid, mcast_print_addr(&grp_addr));
		return (MLD_CLI_ERR_ILL_ADD);
	}

	memcpy(&static_grp.grp_addr, gaddr, sizeof (mcast_grp_addr_t));

	mld_get_ifname(ifname, iftype, if_name);
	memcpy(static_grp.ifname, if_name, INTERFACE_NAMSIZ);
	sg_ret =  mld_add_static_grp_node_to_pending_list(vlan_node, &static_grp,  TRUE, is_ve);

	port_num = mld_get_lif_ifindex_from_ifname(if_name ,vid,type);
	L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] ifname:%s iftype:%d  v->ifindex:0x%x vport:%x sg_rt:%d GA:%s SNP_ADDED:%d SNOOP_ENABLED:%d",
		                    FN, LN, vid, ifname, iftype, vlan_node->ifindex,vport,sg_ret,mcast_print_addr(&grp_addr),
							mld_is_flag_set(vlan_node,  ip_vx_afi, MLD_SNP_ADDED_PROTOCOL),
							mld_is_flag_set(vlan_node, ip_vx_afi, MLD_SNOOPING_ENABLED));
		                
	if (!mld_is_port_member_of_vlan(vlan_node, port_num))
	{
		L2MCD_VLAN_LOG_INFO(vid, "%s:%d:[vlan:%d] port_num:%d if_name:%s not member of vlan",FN, LN, vid,port_num,if_name);
		goto exit;
	}
	if (mld_vdb_vlan_is_present_in_protocol(vlan_node, gaddr->afi)) {
		mcgrp_notify_l2_staticGroup_change(ip_vx_afi, vrfid, &grp_addr,
						   vport,
						   port_num,insert_flag);
	}
exit:
	return (MLD_SUCCESS);
}

/*MLD Static Group unset function*/
    int 
mld_static_group_source_unset(uint32_t vid, char *ifname, int iftype,
        mcast_grp_addr_t * gaddr,
        enum BOOLEAN insert_flag, BOOLEAN is_ve, uint8_t type) 
{
    MADDR_ST    grp_addr;
    ifindex_t   ifindex = 0;
    VRF_INDEX   vrfid = MLD_DEFAULT_VRF_ID;
    int         sg_ret = 0;
    PORT_ID vport;
    mld_vlan_node_t *vlan_node  = NULL; 
    mld_l2_static_group_t   static_grp;
    char if_name[INTERFACE_NAMSIZ];
    uint32_t port_num = 0;

    vlan_node = mld_vdb_vlan_get(vid, type);
    if (!vlan_node) {
        L2MCD_LOG_INFO("%s vid is not available %d %d", __FUNCTION__,
                vid); 
        return (MLD_SUCCESS);
    }

    //  ifindex = mld_get_ifindex_by_ifname(ifname, iftype);
    memcpy(&static_grp.grp_addr, gaddr, sizeof (mcast_grp_addr_t));

    mld_get_ifname(ifname, iftype, if_name);
    memcpy(static_grp.ifname, if_name, INTERFACE_NAMSIZ);
    sg_ret =
        mld_add_static_grp_node_to_pending_list(vlan_node, &static_grp,
                FALSE, is_ve);

    vport = mld_l3_get_port_from_ifindex(vlan_node->ifindex, vlan_node->type);
    mcast_set_ip_addr(&grp_addr, gaddr);

    //port_num = ifindex;
    port_num = mld_get_lif_ifindex_from_ifname(if_name ,vid,type);

    L2MCD_VLAN_LOG_DEBUG(vid, "%s:%d:[vlan:%d] ifname:%s index:%d port_num:%d, GA:%s ", FN,LN,vid, ifname, ifindex, port_num, mcast_print_addr(&grp_addr));
    if (mld_vdb_vlan_is_present_in_protocol(vlan_node, gaddr->afi)) {
        mcgrp_notify_l2_staticGroup_change(gaddr->afi, vrfid, &grp_addr,
                vport,
                port_num,
                insert_flag);
    }
    //exit:
    return (sg_ret);
}

/*Unset MLD Snooping on an interface*/
int
mld_if_snoop_unset(uint32_t afi, uint32_t vid, int user_cfg, uint8_t type)
{
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
	int ret = MLD_SUCCESS;
	mld_vlan_node_t *vlan_node = NULL;
	MADDR_ST any_address;
    MCGRP_L3IF *mcgrp_vport = NULL;
	int rc = 0;
	
	vlan_node = mld_vdb_vlan_get(vid, type);
	if (vlan_node) {
		if (mld_vdb_vlan_is_present_in_protocol(vlan_node, afi)) {
             if (user_cfg) {
                  mld_set_vlan_flag(vlan_node, afi, MLD_IF_CFLAG_SNOOPING_DISABLED);
                  mld_unset_vlan_flag(vlan_node, afi, MLD_IF_CFLAG_SNOOPING_ENABLED);
             }


			if(!user_cfg) {
				L2MCD_LOG_INFO("%s: Setting flag MLD_SNOOPING_DISABLED in vlan node"
						"for vlan %d %d", __FUNCTION__, vid, afi);
				mld_unset_vlan_flag(vlan_node, afi, MLD_SNOOPING_DISABLED);
			    mcast_set_addr_default(&any_address, afi);
				mld_iterate_vlan_group_clear(vlan_node->ivid,
							     &any_address, 0, vlan_node->type);
				mld_del_vlan_from_protocol(MLD_DEFAULT_VRF_ID,
							   mcgrp_glb, vlan_node, afi);
		/* Fusion: Following are not needed since L3 PIM is enabled, we dont want
		 *	to disable the snooping. So just clear the mld_snp_by_usr flag to 
		 *	know that snooping is disabled by CLI, but implicitly present.
		 */
				mld_set_vlan_flag(vlan_node, afi, MLD_SNOOPING_DISABLED);
				mld_unset_vlan_flag(vlan_node, afi, MLD_SNOOPING_ENABLED);
        		mcgrp_vport = mld_get_l3if_from_vlanid(afi, vlan_node->ivid,vlan_node->type);
        		if(mcgrp_vport)
            		UNSET_FLAG(mcgrp_vport->flags, MLD_SNOOPING_ENABLED);
			}
			/* Disable PIM snooping on this vlan */
			rc = mld_pims_if_snoop_unset(afi, vid, TRUE, vlan_node->type);
			if(rc != MLD_SUCCESS)
				L2MCD_LOG_INFO("%s():PIM Snooping: unconfig failed. rc %d", __FUNCTION__, rc);
			if(user_cfg) {
				vlan_node->mld_snp_by_usr[afi-1] = 0;
				vlan_node->pim_snp_by_usr[afi-1] = 0;
			}

            mld_unset_vlan_dcm_flag(vlan_node->gvid, vlan_node->type);
            mld_map_port_add_del(MLD_DEFAULT_VRF_ID,vlan_node->ifindex, FALSE, vlan_node->name,vlan_node->type);
            mld_map_vlan_state(MLD_IP_IPV4_AFI, vlan_node->gvid, FALSE, 1,
                         vlan_node->gvid,  vlan_node->name,vlan_node->type);

		}	
	}

	if (ret != 0)
		L2MCD_LOG_INFO("%s failed for vlan %d", __FUNCTION__,
			       vlan_node->gvid);

	return (ret);
}

/*Set MLD Snooping on an interface*/
int
mld_if_snoop_set(uint32_t afi, uint16_t vid, int user_cfg, uint8_t type)
{
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
	mld_vlan_node_t *vlan_node = NULL;
	int ret = MLD_SUCCESS;
	MCGRP_L3IF *mcgrp_vport = NULL;
    mld_cfg_param_t *cfg;
    char    vlan_name[20] ={};
    uint32_t ifindex;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_LOG_INFO("%s vid is not available %d",
				       __FUNCTION__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}
	L2MCD_LOG_INFO("%s: vid:%d, afi:%d, user_cfg:%d", __FUNCTION__, 
												vid, afi, user_cfg);
    ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vid);
    sprintf(vlan_name,"VLAN%d", vid);
    mld_set_vlan_dcm_flag(vid,type);
    mld_map_port_add_del(MLD_DEFAULT_VRF_ID,ifindex , TRUE, vlan_name,type);
    portdb_set_port_state(mld_portdb_tree, mld_l3_get_port_from_ifindex(ifindex, type), TRUE);
    vlan_node->ifindex = ifindex;
    vlan_node->gvid = vid;
    vlan_node->ivid = vid;
    SET_FLAG(vlan_node->rcvd_nsm_add,MLD_VLAN_NSM);
    mld_portdb_add_gvid(vlan_node->ivid, vlan_node->gvid);
    L2MCD_VLAN_LOG_DEBUG(vid, "%s:%d:[vlan:%d] ifindex:0x%x vlan:%d gvid:%d ifindex:0x%x vrf:%d", 
            FN,LN,vid, ifindex, vid, vlan_node->gvid,vlan_node->ifindex,MLD_DEFAULT_VRF_ID);


	mld_unset_vlan_flag(vlan_node, afi, MLD_SNOOPING_DISABLED);
	mld_set_vlan_flag(vlan_node, afi, MLD_SNOOPING_ENABLED);

    if (user_cfg) {
	        mld_unset_vlan_flag(vlan_node, afi, MLD_IF_CFLAG_SNOOPING_DISABLED);
	        mld_set_vlan_flag(vlan_node, afi, MLD_IF_CFLAG_SNOOPING_ENABLED);
    }


	ret =
	    is_mld_vlan_snooping_allowed(vlan_node->gvid, MLD_DEFAULT_VRF_ID,
					 mld, FALSE, vlan_node->type);
	if (ret == MLD_VLAN_FWD_REF) {
		return (MLD_SUCCESS);
	} else if (ret == MLD_MAX_VLAN_REACHED) {
		mld_unset_vlan_flag(vlan_node, afi, MLD_SNOOPING_ENABLED);
        if (afi == MLD_IP_IPV4_AFI)
            return IGMP_CLI_ERR_MAX_LIMIT_REACHED;
        else
            return IGMP_CLI_ERR_MAX_LIMIT_REACHED;
	} else if (ret == MLD_FAIL) {
		mld_unset_vlan_flag(vlan_node, afi, MLD_SNOOPING_ENABLED);
		return (ret);
	}

	L2MCD_LOG_INFO ("%s: SET flag MLD_SNOOPING_ENABLED in vlan node for vlan %d, cfg_version:%d",
		 __FUNCTION__, vid, vlan_node->mld_cfg[afi-1]->param->cfg_version);

	cfg = mld_vdb_vlan_get_cfg_param(vlan_node, TRUE, afi);

	if (!cfg) {
		L2MCD_LOG_INFO("%s %d malloc error", __FUNCTION__, __LINE__);
		return MLD_CLI_ERR_NO_SUCH_IFF;
	}
	/* Set the default version IGMP_VERSION_2, if it is set to 0 */
	if (afi == MLD_IP_IPV4_AFI) {
		if(cfg->cfg_version == IGMP_VERSION_NONE)
			cfg->cfg_version = IGMP_VERSION_2;
	} else if (afi == MLD_IP_IPV6_AFI) {
		if(cfg->cfg_version == MLD_VERSION_NONE)
			cfg->cfg_version = MLD_VERSION_1;
	}

	if(user_cfg) {
		mld_add_vlan_to_protocol(MLD_DEFAULT_VRF_ID, mcgrp_glb,
			vlan_node, MLD_SNOOPING, afi);
		vlan_node->mld_snp_by_usr[afi-1] = user_cfg;	//user configured flag
    }
	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vlan_node->ivid,vlan_node->type);
	
    if(mcgrp_vport) {
		SET_FLAG(mcgrp_vport->flags, MLD_SNOOPING_ENABLED);
		mcgrp_vport->cfg_version  = cfg->cfg_version;
		mcgrp_vport->oper_version = (mcgrp_vport->cfg_version == IGMP_VERSION_NONE) ?
			mld->oper_version : mcgrp_vport->cfg_version;
		mcgrp_vport->type =  type;
	}

	if (ret != 0)
		L2MCD_LOG_INFO("%s failed for vlan %d", __FUNCTION__, vlan_node->gvid);

	return (ret);
}

/* Wrapper function to handle add/delete port from VLAN event */
int
mld_map_port_vlan_state(uint32_t vlan_id, uint32_t ifindex, int add_port,
									uint32_t ip_family, uint8_t type, int lif_type, int lif_state)
{
    int rc = MLD_SUCCESS;
    UINT16  vlan_port;
    UINT32 port;
	ifindex_t vlan_ifindex;
	MCGRP_PORT_ENTRY *mcgrp_pport = NULL;
	MCGRP_L3IF    *mcgrp_vport;
    MCGRP_CLASS   *mcgrp;
	mld_vlan_node_t *vlan_node = NULL;
	uint8_t afi;

	vlan_node = mld_vdb_vlan_get(vlan_id, type);
	if (!vlan_node) {
		L2MCD_LOG_INFO("%s %d is not available %x %d", __FUNCTION__,
			       vlan_id, ifindex, add_port);
		return (MLD_ERROR); 
	}
	port = ifindex;
	vlan_ifindex = vlan_node->ifindex;
	vlan_port = mld_l3_get_port_from_ifindex(vlan_ifindex,vlan_node->type);

	if (add_port) {
        rc = mld_vdb_add_port_to_vlan(mld_vlan_get_db(), vlan_id, port, type);
        L2MCD_VLAN_LOG_INFO(vlan_node->gvid, "%s:%d:[vlan:%d] vlan_flag:%x,%x ivid:%d port:%d vlan_ifindex:%x vlan_port:%d",FN,LN,vlan_id,
                mld_vdb_vlan_is_present_in_protocol(vlan_node, MCAST_IPV4_AFI),
                mld_vdb_vlan_is_present_in_protocol(vlan_node, MCAST_IPV6_AFI),
                vlan_node->ivid, port, vlan_ifindex, vlan_port);
        for (afi = L2MCD_IPV4_AFI; afi <= MCAST_AFI_MAX; afi++)
		{
			if (mld_vdb_vlan_is_present_in_protocol(vlan_node, afi)) {
				mcgrp =
				    MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi,
								     MLD_DEFAULT_VRF_ID);
				mcgrp_vport =
				    IS_IGMP_CLASS(mcgrp) ?
				    gIgmp.port_list[vlan_port]
				    : gMld.port_list[vlan_port];

				if (mcgrp_vport) {
					mcgrp_pport = mcgrp_add_phy_port (mcgrp, mcgrp_vport, port);

                    L2MCD_VLAN_LOG_INFO (vlan_node->gvid, "%s:%d:[vlan:%d] Port:%d PPORT:%p LIF:%d LIF_State:%d",
                            FN, LN,vlan_id, port, mcgrp_pport, lif_type, lif_state);

                    if (lif_type)
                        mcgrp_pport->is_up = lif_state;

					/* Port State Notify if LIF is UP */
					if ((mcgrp_pport) && (mcgrp_pport->is_up)) {
						mld_protocol_port_state_notify (vlan_node, afi, mcgrp, port, TRUE);
					}
				} else {
					L2MCD_LOG_INFO ("%s %d %x %x", __FUNCTION__, vlan_port, vlan_ifindex, ifindex);
				}
			}
		}
	} else {
        L2MCD_VLAN_LOG_INFO(vlan_node->gvid, "%s:%d:[vlan:%d] %x %x %d ", __FUNCTION__, __LINE__,
                vlan_id, mld_vdb_vlan_is_present_in_protocol(vlan_node, MCAST_IPV4_AFI),
                mld_vdb_vlan_is_present_in_protocol(vlan_node, MCAST_IPV6_AFI),port);
        for (afi = 1; afi <= MCAST_AFI_MAX; afi++) {
			if (mld_vdb_vlan_is_present_in_protocol(vlan_node, afi)) {
				mld_static_grp_deconfig_port(vlan_node, ifindex,
							     port, afi);
				mcgrp =
				    MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi,
								     MLD_DEFAULT_VRF_ID);
                
                if (vlan_node && mld_is_flag_set(vlan_node, afi, MLD_SNOOPING_ENABLED))
                    mcgrp_vport_state_notify(mcgrp, vlan_port, port, FALSE);

				mcgrp_vport =
				    IS_IGMP_CLASS(mcgrp) ?
				    gIgmp.port_list[vlan_port]
				    : gMld.port_list[vlan_port];
				if (mcgrp_vport)
					mcgrp_delete_veport(mcgrp, mcgrp_vport,
							    port);
			}
		}
		rc = mld_vdb_del_port_frm_vlan(mld_vlan_get_db(), vlan_id,
					       port, type);
	}

    return rc;
}

/*Unset MLD Snooping Querier*/
int
mld_snoop_querier_unset(uint32_t afi, uint16_t vid, uint8_t type)
{
    int ret = MLD_SUCCESS;
	MCGRP_L3IF *mcgrp_vport = NULL;
    VRF_INDEX        vrf_index = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index);
	mld_vlan_node_t *vlan_node  = NULL;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
        goto EXIT;
    }
  
	mld_unset_vlan_flag(vlan_node, afi, MLD_SNOOPING_QUERIER_ENABLED);
	if (!vlan_node->ivid
	    || !mld_vdb_vlan_is_present_in_protocol(vlan_node, afi)) {
		L2MCD_LOG_INFO("%s %d %d %d %d", __FUNCTION__, __LINE__, vid,
			       vlan_node->ivid, afi);
		goto EXIT;
	}
	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vlan_node->ivid, type);
	if (!mcgrp_vport) {
		goto EXIT;
	}

	/*Unset snooping querier flag */
	if (is_mld_snooping_querier_enabled(mcgrp_vport)) {
      UNSET_FLAG(mcgrp_vport->flags, MLD_SNOOPING_QUERIER_ENABLED);
		if (!is_mld_l3_configured(mcgrp_vport))
			mcgrp_vport_stop_querier_process(mcgrp, mcgrp_vport, TRUE);
		L2MCD_LOG_INFO
		    ("%s(): MLD_SNOOPING_QUERIER_ENABLED flag UNSET vlanid=%d %d",
		     __FUNCTION__, vid, afi);
	}

      EXIT:
	return (ret);
}

/*Set fastleave*/
int
mld_fastleave_set(uint32_t afi, uint32_t vid, uint8_t type)
{
    int ret = MLD_SUCCESS;
    mld_vlan_node_t *vlan_node  = NULL;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_LOG_INFO("%s vid is not available %d",
				       __FUNCTION__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

	mld_set_vlan_flag(vlan_node, afi, MLD_FAST_LEAVE_CONFIGURED);

	if (vlan_node->ivid
	    && mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
		ret = mld_proto_fastleave_set(afi, vlan_node->ivid, vlan_node->type);
	else
		L2MCD_LOG_INFO("%s %d %d %d %d", __FUNCTION__, __LINE__, vid,
			       vlan_node->ivid, afi);

	return (ret);
}

/*Unset fastleave*/
int
mld_fastleave_unset(uint32_t afi, uint32_t vid, uint8_t type)
{
    int ret = MLD_SUCCESS;
	MCGRP_L3IF *mcgrp_vport = NULL;
    mld_vlan_node_t *vlan_node  = NULL;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node)
		goto EXIT;
    
	mld_unset_vlan_flag(vlan_node, afi, MLD_FAST_LEAVE_CONFIGURED);
	if (!vlan_node->ivid
	    || !mld_vdb_vlan_is_present_in_protocol(vlan_node, afi)) {
		L2MCD_LOG_INFO("%s %d %d %d", __FUNCTION__, __LINE__, vid,
			       vlan_node->ivid);
		goto EXIT;
	}

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vlan_node->ivid, type);
	if (!mcgrp_vport) {
		goto EXIT;
	}

	if (is_mld_fast_leave_configured(mcgrp_vport)) {
		UNSET_FLAG(mcgrp_vport->flags, MLD_FAST_LEAVE_CONFIGURED);
		L2MCD_LOG_INFO("%s(): MLD_FAST_LEAVE_CONFIGURED flag UNSET"
			       " for vlanid=%d", __FUNCTION__, vid);
	}

 EXIT:
	return (ret);
}

/*Set MLD Snooping Querier*/
int
mld_snoop_querier_set(uint32_t afi, uint16_t vid, uint8_t type)
{
    int ret = MLD_SUCCESS;
	mld_vlan_node_t *vlan_node  = NULL;

	vlan_node = mld_vdb_vlan_get(vid, type);
	if (!vlan_node) {
		vlan_node = mld_vlan_create_fwd_ref(vid, type);
		if (!vlan_node) {
			L2MCD_LOG_INFO("%s vid is not available %d",
				       __FUNCTION__, vid);
			return MLD_CLI_ERR_NO_SUCH_IFF;
		}
	}

	mld_set_vlan_flag(vlan_node, afi, MLD_SNOOPING_QUERIER_ENABLED);
	if (vlan_node->ivid
	    && mld_vdb_vlan_is_present_in_protocol(vlan_node, afi))
		ret = mld_proto_snoop_querier_set(afi, vlan_node->ivid,vlan_node->type);
	else
		L2MCD_LOG_INFO("%s %d %d %d %d", __FUNCTION__, __LINE__, vid,
			       vlan_node->ivid, afi);

	return (ret);
}

char * mld_get_if_name_from_port(uint16_t port_id)
{
	return (portdb_get_ifname_from_portindex(port_id));
}

/*This Function returns mcgrp_vport(MCGRP_L3IF) corresponding to a vlan*/
MCGRP_L3IF * mld_get_l3if_from_vlanid(UINT32 afi, UINT32 vid, uint8_t type)
{
    MCGRP_CLASS *mcgrp = NULL;
    MCGRP_L3IF *mcgrp_vport = NULL;
    UINT16 vport = 0;
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	uint32_t gvid = 0;
    mld_vlan_node_t *vlan_node = NULL; 
	
    mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	if (!mcgrp) {
		L2MCD_LOG_INFO("%s(): mcgrp is NULL", __FUNCTION__);
		return (NULL);
	}
	
	gvid = mld_get_gvid(vid);
	L2MCD_LOG_INFO("%s(%d) gvid:0x %x ", __FUNCTION__, __LINE__, gvid);
	vlan_node = mld_vdb_vlan_get(gvid, type);
	if(!vlan_node)
		return NULL;
/*
    ifindex_t ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vid);
	if (ifindex == 0) {
		L2MCD_LOG_INFO("%s(): ifindex is zero for vlanid=%d",
			       __FUNCTION__, vid);
		return (NULL);
    }

    vport = l3_get_port_from_ifindex(ifindex);
*/
	vport = mld_l3_get_port_from_ifindex(vlan_node->ifindex,vlan_node->type);
	L2MCD_LOG_INFO("%s(%d) ifindex:0x %x vport %d ", 
		__FUNCTION__, __LINE__, vlan_node->ifindex, vport);
	mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vport] :
														gMld.port_list[vport];

	if (!mcgrp_vport) {
		L2MCD_LOG_INFO
		    ("%s(%d): mcgrp_vport is NULL for vlanid=%d. vport %d Probably MLD"
		     " Snooping Not Enabled", __FUNCTION__, LN, vid, vport);
		return (NULL);
	} else {
		L2MCD_LOG_INFO("%s(): mcgrp_vport FOUND for vlanid=%d",
			       __FUNCTION__, vid);
		return (mcgrp_vport);
	}
}

void mcast_set_address(mcast_grp_addr_t * gaddr, MADDR_ST * grp_addr)
{
	gaddr->afi = grp_addr->afi;
	if (gaddr->afi == MCAST_IPV4_AFI)
		gaddr->ip.ipv4_addr = grp_addr->ip.v4addr;
	else
		memcpy(&gaddr->ip.ipv6_addr, &grp_addr->ip.v6addr,
		       sizeof (struct in6_addr));
}

mld_l3_if_type_t mld_get_l3if_type(ifindex_t ifIndex)
{
    mld_l3_if_type_t ifType = 0;

    if (l2mcd_ifindex_is_svi(ifIndex)) {
        ifType = MLD_IFTYPE_L3SVI;
    } else if (l2mcd_ifindex_is_physical(ifIndex)) {
        ifType = MLD_IFTYPE_L3PHY;
    } else {
        L2MCD_LOG_INFO("%s Interface type other", __FUNCTION__);
        ifType = MLD_IFTYPE_OTHER;
    }
    return ifType;
}

void mcgrp_vport_stop_querier_process(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport, bool_t from_snooping)
{
	mld_cfg_param_t *cfg;
	mld_vlan_node_t *vlan_node = NULL;
	mld_vid_t gvid;

	L2MCD_LOG_INFO("%s()", __FUNCTION__);
    if (mcgrp == NULL || mcgrp_vport == NULL)
        return;

    mcgrp_vport->querier = FALSE;

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_SNOOP_STARTUP_QUERY_COUNT))
		mcgrp_vport->start_up_query_count = mcgrp_vport->robustness_var;
	else {
		gvid = mld_get_vlan_id(mcgrp_vport->vir_port_id);
		vlan_node = mld_vdb_vlan_get(gvid, mcgrp_vport->type);
		cfg = mld_vdb_vlan_get_cfg_param(vlan_node, FALSE, mcgrp->afi);
		if (cfg)
			mcgrp_vport->start_up_query_count =
			    cfg->start_up_query_count;
		else
			mcgrp_vport->start_up_query_count =
			    mcgrp_vport->robustness_var;
    }

    if (WheelTimerSuccess ==
                 WheelTimer_IsElementEnqueued(&mcgrp_vport->vport_tmr.mcgrp_wte))
        WheelTimer_DelElement(mcgrp->mcgrp_wtid,
                              &mcgrp_vport->vport_tmr.mcgrp_wte);

    //call the routine to start the snooping querier if it is enabled
    if(!from_snooping)
	    mcgrp_start_stop_snooping_querier_api (mcgrp, mcgrp_vport, mcgrp->afi, TRUE);
}

int mld_iterate_vlan_group_clear(mld_vid_t ivid, MADDR_ST * grp_addr_clr,
			     int clr_grp_flag, uint8_t vlan_type)
{
	struct listnode *node = NULL;
	mld_vlan_node_t *vlan_node = NULL;
	unsigned long gvid = 0;
	int ret = MLD_SUCCESS;
    struct listnode *list_node;
    mld_l2_static_group_t *static_grp;
	struct list *s_list;
	uint32_t ifindex =0;

    if (!clr_grp_flag)
        received_clear_grp_notify = TRUE;

    if (received_clear_grp_notify) {
		/* TR000600799 : Skip sending mcastss if it is physical router port */
		if(!l2mcd_ifindex_is_physical(ivid)) {
			MLD_LOG(MLD_LOGLEVEL7, grp_addr_clr->afi, "%s(%d) Sending to McastSS group clear.", FN, LN);
			mld_send_l2mcd_sync_group_clr(ivid, TRUE, grp_addr_clr->afi);
		}
    }

    if (ivid != 0) {
		//For Physical ifindex ivid is ifindex vs. vlan_id 
		if(l2mcd_ifindex_is_physical(ivid)) {
			ifindex = ivid;
		} else if(vlan_type == MLD_BD) {
            mld_lookup_gvid_by_ivid(NULL, ivid, &gvid);
            ifindex = gvid;
		} else
			ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, ivid);
		
		ret = mld_vlan_clear_group(ifindex, grp_addr_clr, clr_grp_flag,vlan_type);
    } else {
		LIST_LOOP(snooping_enabled_vlans[grp_addr_clr->afi - 1],
			  vlan_node, node) {
            /*Skip rputer ports here*/
            if(l2mcd_ifindex_is_physical(vlan_node->ifindex)){
                continue;
            }

			ret =
			    mld_vlan_clear_group(vlan_node->ifindex, grp_addr_clr,
						 clr_grp_flag,vlan_node->type);
		
		    s_list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, grp_addr_clr->afi, TRUE);
			LIST_LOOP(s_list, static_grp, list_node) 
				mld_vlan_clear_group(vlan_node->ifindex, (MADDR_ST *)&static_grp->grp_addr, 
						clr_grp_flag, vlan_node->type);
		}

    }

    if (received_clear_grp_notify) {
        received_clear_grp_notify = FALSE;
    }

    return ret;
}

void mld_del_vlan_from_protocol(int vrfid, MCGRP_GLOBAL_CLASS * mcgrp_glb,
			   mld_vlan_node_t * vlan_node, int afi)
{
	ifindex_t ifindex = vlan_node->ifindex;
	int ret = 0;
	MCGRP_L3IF *mcgrp_vport;
	MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	uint16_t port = mld_l3_get_port_from_ifindex(ifindex, vlan_node->type);

	L2MCD_LOG_INFO("%s(%d) %d %d", __FUNCTION__, __LINE__, mcgrp_glb->mld_snp_vlan_count,
										mcgrp_glb->g_snooping_enabled);
	/* First remove the MLD config */
	MLD_SNP_VLAN_COUNT_DEC(mcgrp_glb, vlan_node, afi);
	mld_unset_vlan_flag(vlan_node, afi, MLD_SNP_ADDED_PROTOCOL);


	if (!is_mld_vlan_l3_enabled(vlan_node, afi)) {
		mcgrp_vport =
		    IS_IGMP_CLASS(mld) ? gIgmp.
		    port_list[port] : gMld.port_list[port];
		if (mcgrp_vport) {
			mcgrp_delete_l2_staticGroup_if(mld, mcgrp_vport);
			ret =
			    mld_map_set_if_mld_mode(afi, ifindex, FALSE, vrfid, vlan_node->type);
			if(ret != 0)
				MLD_LOG(MLD_LOGLEVEL7,MLD_IP_IPV4_AFI,"%s(%d) set_if_mld_mode returned err.\n", FN, LN);	
		}
	}

	return;
}

void mld_add_vlan_to_protocol(int vrfid, MCGRP_GLOBAL_CLASS * mcgrp_glb,
			 mld_vlan_node_t * vlan_node, mld_if_type_t mode,
			 uint8_t afi)
{
	ifindex_t ifindex = vlan_node->ifindex;
	    //l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_node->ivid);
	//uint32_t port, pport, port_num;
	uint32_t port, pport;
    mld_vlan_port_t *vlan_port;
	MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	MCGRP_L3IF *mcgrp_vport = NULL;

	port = mld_l3_get_port_from_ifindex(ifindex, vlan_node->type);

	L2MCD_LOG_INFO("%s port:%x ifindex:%x", __FUNCTION__, port, ifindex);

	mcgrp_vport =
	    IS_IGMP_CLASS(mld) ? gIgmp.port_list[port] : gMld.port_list[port];
	mld_set_vlan_flag(vlan_node, afi, MLD_SNP_ADDED_PROTOCOL);
	if (!mcgrp_vport) {
		if (!mld_port_exist_in_port_db(port)) {
			mld_map_port_add_del(vrfid, ifindex, TRUE,
					     vlan_node->name,vlan_node->type);
			portdb_set_port_state(mld_portdb_tree,
					      mld_l3_get_port_from_ifindex(ifindex,vlan_node->type),
					      TRUE);
		}
	} else {
		if (mcgrp_vport->is_up) {
			L2MCD_LOG_INFO("%s(%d) mcgrp_vport exist and it is UP. AFI:%d  ", __FUNCTION__, __LINE__, afi);
			memcpy(&mcgrp_vport->flags, &vlan_node->flags[afi - 1],
				    sizeof (int));
			return;
		}
	}

	if (mode == MLD_SNOOPING) {
		//mld_vcs_create_local_vlan(vlan_node->gvid, afi);
		MLD_SNP_VLAN_COUNT_INC(mcgrp_glb, vlan_node, afi);
		//mld_vlan_add_list(vlan_node);
		mld_map_set_if_mld_mode(mld->afi, ifindex, TRUE, vrfid, vlan_node->type);
		mcgrp_vport =
		    IS_IGMP_CLASS(mld) ? gIgmp.
		    port_list[port] : gMld.port_list[port];

		if (mcgrp_vport) {
			L2MCD_LOG_INFO("%s(%d) setting the flags on vport for ivid: %d ", __FUNCTION__, __LINE__,
				       vlan_node->ivid);
			memcpy(&mcgrp_vport->flags, &vlan_node->flags[afi - 1],
			    sizeof (int));
			mcgrp_vport->cfg_version = vlan_node->mld_cfg[afi-1]->param->cfg_version; //Assign Cfg version (IGMPv1/v2/v3) to L3IF.
     		mcgrp_vport->oper_version = (mcgrp_vport->cfg_version == IGMP_VERSION_NONE) ?
									mld->oper_version : mcgrp_vport->cfg_version;
            mcgrp_vport->type = vlan_node->type;  

		}
	}

	if (!mcgrp_vport) {
		L2MCD_LOG_INFO("%s(%d) vlan port could not get create ivid: %d",
			       __FUNCTION__, __LINE__, vlan_node->ivid);
		return;
	}

	for (vlan_port = M_AVLL_FIRST(vlan_node->port_tree); vlan_port;
		vlan_port = M_AVLL_NEXT(vlan_node->port_tree, vlan_port->node)) 
	{
		pport = vlan_port->ifindex;	

		mcgrp_add_phy_port (mld, mcgrp_vport, pport);

		L2MCD_LOG_INFO("%s ivid %d port:%x pport:%x State:%d", __FUNCTION__,
			vlan_node->ivid, port, pport, vlan_port->lif_state);

		/* Check LIF is UP */
		if (vlan_port->lif_state)
			mcgrp_vport_state_notify (mld, mcgrp_vport->vir_port_id, pport, TRUE);
	}

	mld_replay_config (vlan_node, mld->afi, mld);
}

void mcgrp_vport_start_querier_process(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport)
{
	uint32_t ipv4_addr = 0;
	portdb_entry_t *port_entry;
	UINT32 send_port = 0;
	uint32_t ifindex = 0;
	mld_vlan_node_t *vlan_node = NULL; 
	mld_vid_t gvid; 
	int port_id = 0;
	bool_t ve_db_lkup = FALSE;

	if (mcgrp == NULL || mcgrp_vport == NULL)
	{
        L2MCD_LOG_INFO("%s:%d mcgrp/vport NULL", __FUNCTION__, __LINE__);
		return;
	}
	gvid = mld_get_vlan_id(mcgrp_vport->vir_port_id); 
	vlan_node = mld_vdb_vlan_get(gvid, mcgrp_vport->type);  

	port_entry = portdb_find_port_entry(mld_portdb_tree, mcgrp_vport->vir_port_id);

	if (!port_entry)
	{
		L2MCD_LOG_NOTICE("%s:%s virport:0x%x coundnt find port_entry", __FUNCTION__, __LINE__, mcgrp_vport->vir_port_id);
		return;
	}
	if (!vlan_node)
	{
		L2MCD_LOG_NOTICE("%s:%s gvid:0x%x coundnt find vlan_node", __FUNCTION__, __LINE__, gvid);
		return;
	}

	/*
	 * Check whether VLAN-VE binding is present.
	 * If yes and if vlan id and ve id are different then, use the ip address of VE interface 
	 */                                                                                                                                                                                                                                                                 
	if (mcgrp_vport->is_ve) {          
		/* Vlan-id and VE ID are same */
		if (vlan_node->ifindex == vlan_node->ve_ifindex) {           
			port_id = mcgrp_vport->vir_port_id;    
			ve_db_lkup = TRUE;
		} else {
			/* Vlan and VE ID are different so, use port-id of VE to retrive IP address from mld_portdb_tree */
			port_id = l3_get_port_from_ifindex(vlan_node->ve_ifindex);
			L2MCD_LOG_INFO("%s(%d) VE-VLAN binded. VE_portid = %d Ve_ifindex = 0x%x", __FUNCTION__, __LINE__, port_id, vlan_node->ve_ifindex);
			ve_db_lkup = TRUE;
		}                                                                                        
	} else
		port_id = mcgrp_vport->vir_port_id;

	if (mcgrp_vport->querier == FALSE) 
		mcgrp_vport->querier = TRUE;

	if (mcgrp->afi == IP_IPV4_AFI) {
		if (!ve_db_lkup)
			ipv4_addr = mld_portdb_get_port_lowest_ipv4_addr_from_list(port_id);
		else {
			if(l2mcd_ifindex_is_physical(vlan_node->ifindex)) {
				ipv4_addr = mld_portdb_get_port_lowest_ipv4_addr_from_list(port_id);
				//L2MCD_LOG_INFO("%s(%d): physical port_id:%d ipv4_addr:0%x ", __FUNCTION__, LN, port_id, ipv4_addr);
			}else {		
				ipv4_addr = ve_mld_portdb_get_port_lowest_ipv4_addr_from_list(port_id);
				//L2MCD_LOG_INFO("%s(%d): VE DB lookup port_id:%d ipv4_addr:0%x ", __FUNCTION__, LN, port_id, ipv4_addr);
			}
		}


		if (!IPV4_ADDR_SAME(&ipv4_addr, &mcgrp_vport->querier_router.ip.v4addr)) {
			mcgrp_vport->querier_router.afi = IP_IPV4_AFI;
			mcgrp_vport->querier_router.ip.v4addr = ipv4_addr;
		} else {
			if (!mcgrp_vport->querier_router.ip.v4addr) {
				mcgrp_vport->querier_router.ip.v4addr = ipv4_addr;
				mcgrp_vport->querier_router.afi = IP_IPV4_AFI;
			}
		}
		MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, "%s(%d) port_id:%d ifindex:0x%x querier_ip:0x%x  ", 
				FN, LN, port_id, vlan_node->ifindex, mcgrp_vport->querier_router.ip.v4addr);

	} else if (mcgrp->afi == IP_IPV6_AFI) {
        //MLD
	}

	ifindex = portdb_get_port_ifindex(mld_portdb_tree, mcgrp_vport->vir_port_id);

	L2MCD_LOG_INFO ("%s(%d): gvid:%d vport:%d  ifindex:0x%x oper_ver:%d flags:%x", __FUNCTION__,
		__LINE__, mld_get_vlan_id(mcgrp_vport->vir_port_id), mcgrp_vport->vir_port_id,
		ifindex, (UINT8) mcgrp_vport->oper_version, mcgrp_vport->flags);

	if(l2mcd_ifindex_is_physical(ifindex)) {
		send_port = ifindex; 
	} else {
		send_port = PORT_INDEX_INVALID;
    }

	if (IS_IGMP_CLASS(mcgrp)) {
		igmp_send_general_query(mcgrp, mcgrp_vport->vir_port_id, send_port, (UINT8) mcgrp_vport->oper_version, 
				mcgrp_vport->querier_router.ip.v4addr,	/* Use lowest srcIp */
				(mcgrp_vport->max_response_time *
				 10));
	} else {
        //MLD
	}
	if (mcgrp_vport->start_up_query_count > 0)
		mcgrp_vport->start_up_query_count--;

	// Query interval time may be overwritten by previous Querier, reinitialized
	// it to the current usr cfg query interval. cfg_query_interval is init to 
	// default 125 at startup

	mcgrp_vport->query_interval_time = mcgrp_vport->cfg_query_interval_time;

	if (WheelTimerSuccess == WheelTimer_IsElementEnqueued(&mcgrp_vport->vport_tmr.mcgrp_wte))
	{
		WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid,
				&mcgrp_vport->vport_tmr.mcgrp_wte,
				((mcgrp_vport->start_up_query_count > 0) ?
				 (mcgrp_vport->start_up_query_interval) :
				 mcgrp_vport->query_interval_time));
	   L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id,"%s:%d:[vlan:%d] strt_qry_count:%d strt_qry_interval:%d strt_qry_interval_time:%d",
                    FN,LN,mcgrp_vport->vir_port_id,mcgrp_vport->start_up_query_count,mcgrp_vport->start_up_query_interval,mcgrp_vport->query_interval_time);
	}
	else 
	{
		// Add to the wheel timer.
		mcgrp_vport->vport_tmr.timer_type            = MCGRP_WTE_QUERIER;
		mcgrp_vport->vport_tmr.mcgrp                 = mcgrp;
		mcgrp_vport->vport_tmr.wte.vport.mcgrp_vport = mcgrp_vport;
		mcgrp_vport->vport_tmr.mcgrp_wte.data        = &mcgrp_vport->vport_tmr;

		WheelTimer_AddElement(mcgrp->mcgrp_wtid,
				&mcgrp_vport->vport_tmr.mcgrp_wte,
				((mcgrp_vport->start_up_query_count > 0) ?
				 (mcgrp_vport->start_up_query_interval) :
				 mcgrp_vport->query_interval_time));
    	L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id,"%s:%d:[vlan:%d] strt_qry_count:%d strt_qry_interval:%d strt_qry_interval_time:%d",
                    FN,LN,mcgrp_vport->vir_port_id,mcgrp_vport->start_up_query_count,mcgrp_vport->start_up_query_interval,mcgrp_vport->query_interval_time);
	}
}

int mld_pims_if_snoop_unset(uint32_t afi, uint16_t vid, BOOLEAN user_cfg, uint8_t type)
{
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	MCGRP_GLOBAL_CLASS *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
	mld_vlan_node_t *vlan_node = NULL;
	
	vlan_node = mld_vdb_vlan_get(vid, type);
	if(vlan_node)
	{
		if(user_cfg) {
			vlan_node->pim_snp_by_usr[afi-1] = 0;
			L2MCD_LOG_INFO("%s: L3 is enabled. vid:%d,afi:%d, user_cfg:%d", 
										__FUNCTION__, vid, afi, user_cfg);
			return MLD_SUCCESS;
		}
		/* Clear the grp DB for this vlan */
		pims_clear_snoop_cache(afi, vid, NULL,type);
		mld_unset_vlan_flag(vlan_node, afi, MLD_PIM_SNOOP_ENABLED);
		mld_set_vlan_flag(vlan_node, afi, MLD_PIM_SNOOP_DISABLED);
		mcgrp_glb->pims_snp_vlan_count--;
		if(user_cfg)
			vlan_node->pim_snp_by_usr[afi-1] = 0;
		pims_clear_statistics(afi, vid,type);
	}
	else
		L2MCD_LOG_INFO("%s():PIMS: vlan_node not found for vid %d, afi %d", 
													__FUNCTION__, afi, vid);
		
	return MLD_SUCCESS;
}

/*
 * This function returns true if the source is present in 
   include/exclude or pim snooping source list.
 */
BOOLEAN mld_snp_is_source_present_on_mbr_port(MCGRP_MBRSHP *grp_mbrshp,
						uint32_t src_addr, uint8_t afi)
{
	uint8_t include_flag = 0 , exclude_flag = 0;

	return ((mld_snp_is_igmpv3_source_present_on_mbr_port(grp_mbrshp, src_addr, afi , &include_flag, &exclude_flag))
			|| (pim_snoop_is_source_present_on_mbr_port(grp_mbrshp, src_addr, afi)));
}

BOOLEAN mld_is_snoop_mbrship_present(MCGRP_MBRSHP *mcgrp_mbrshp, 
				uint8_t *v1_mbr, uint8_t *v2_mbr, uint8_t *v3_mbr)
{
	if(!mcgrp_mbrshp || !v1_mbr || !v2_mbr || !v3_mbr)
		return FALSE;

	if((mcgrp_mbrshp->pims_mbr_flags & MLD_OR_IGMP_JOIN_PORT)) {
		if(mcgrp_mbrshp->pims_mbr_flags & IGMP_V1_MBR_PORT)
			*v1_mbr = 1;
		if(mcgrp_mbrshp->pims_mbr_flags & IGMP_V2_MBR_PORT)
			*v2_mbr = 1;
		if(mcgrp_mbrshp->pims_mbr_flags & IGMP_V3_MBR_PORT)
			*v3_mbr = 1;

		return TRUE;
	}
	
	return FALSE;
}

/*
 * This function searches for a given source on a give member port
 * (*include_flag) will be set if source found in INCLUDE list
 * (*exclude_flag) will be set if source found in ExCLUDE list
 */
BOOLEAN mld_snp_is_igmpv3_source_present_on_mbr_port(MCGRP_MBRSHP *grp_mbrshp,
						uint32_t src_addr, uint8_t afi, 
						uint8_t *include_flag, uint8_t *exclude_flag)
{
	MCGRP_SOURCE *src_entry, *next_entry;
	int i;
	if(!grp_mbrshp || (src_addr == 0) || !include_flag || !exclude_flag)
		return FALSE;

	//consider both INCL and EXCL lists
	for(i=FILT_INCL; i<= FILT_EXCL; i++ ) {
		src_entry = grp_mbrshp->src_list[i];
		while (src_entry) {
			next_entry  = src_entry->next;
			if(src_entry->src_addr.ip.v4addr == src_addr) {
				if(i==FILT_INCL) 
					*include_flag = 1;	//found in include list
				else 
					*exclude_flag = 1;

				return TRUE;
			}
			src_entry  = next_entry;
		}
	}

	return FALSE;
}

char *
mld_ntop(mcast_grp_addr_t * addr, char *str)
{
	MLD_LOG(MLD_LOGLEVEL9, addr->afi,"%s %d %d %d", __FUNCTION__, addr->afi, AF_INET, AF_INET6);
	if (MCAST_IPV4_AFI == addr->afi) {
        int tmp_addr = 0;
		tmp_addr = htonl(addr->ip.ipv4_addr);
		inet_ntop(AF_INET, ((struct in_addr *) &tmp_addr),
			  (char *) str, INET_ADDRSTRLEN);
		str[INET_ADDRSTRLEN] = '\0';
	} else if (MCAST_IPV6_AFI == addr->afi) {
		inet_ntop(AF_INET6, (struct in6_addr *) &addr->ip.ipv6_addr,
			  (char *) str, INET6_ADDRSTRLEN);
	}
	return str;
}

mld_vlan_node_t *mld_vlan_node_get(uint32_t vid)
{
	mld_vlan_node_t *vlan_node = NULL;
	vlan_node = mld_vdb_vlan_get(vid, MLD_VLAN);
	if (!vlan_node) 
	{
		return NULL;

    }
	return vlan_node;
}

void mld_map_vlan_state(uint32_t ip_family, uint32_t gvid, int add,
						uint32_t flags, uint16_t ivid, char *vlan_name,uint8_t type)
{
	int  	vrfid = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mld;
	MCGRP_GLOBAL_CLASS *mcgrp_glb;
	mld_vlan_node_t *vlan_node = NULL;
	uint8_t afi;
	MADDR_ST any_address;

	if (add) {
		vlan_node =
		    mld_vdb_vlan_create(mld_vlan_get_db(), gvid, type, 0,
					flags, ivid, vlan_name, MLD_VLAN_NSM);
		if (!vlan_node) {
			L2MCD_LOG_INFO("%s vlan could not be created %d %d",
				       __FUNCTION__, gvid, ivid);
			return;
		} else {
			for (afi = 1; afi <= MCAST_AFI_MAX; afi++) {
				mld_unset_vlan_flag(vlan_node, afi,
						  MLD_VLAN_DELETED);
				mld =
				    MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi,
								     vrfid);
				mcgrp_glb =
				    (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
				if (is_mld_vlan_snooping_allowed
				    (gvid, MLD_DEFAULT_VRF_ID, mld,
				     TRUE, vlan_node->type) == MLD_SUCCESS)
					mld_add_vlan_to_protocol
					    (MLD_DEFAULT_VRF_ID, mcgrp_glb,
					     vlan_node, MLD_SNOOPING, afi);
			}
		}
	} else {
		vlan_node = mld_vdb_vlan_get(gvid,type);
		if (vlan_node) {
			for (afi = IP_IPV4_AFI; afi <= IP_IPV4_AFI; afi++) {
				mld_set_vlan_flag(vlan_node, afi,
						  MLD_VLAN_DELETED);
				mld =
				    MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi,
								     vrfid);
				mcgrp_glb =
				    (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
				if (mld_vdb_vlan_is_present_in_protocol
				    (vlan_node, afi)) {
					mcgrp_reset_mld_stats(mld,
							      vlan_node->ifindex,vlan_node->type);
					mcast_set_addr_default(&any_address,
							       afi);
					mld_iterate_vlan_group_clear
					    (vlan_node->ivid, &any_address, 0,vlan_node->type);
					mld_del_vlan_from_protocol(vrfid,
								   mcgrp_glb,
								   vlan_node,
								   afi);
				}
			}
			L2MCD_LOG_INFO("%s(%d) %d %d", __FUNCTION__, __LINE__,
				       CHECK_FLAG(vlan_node->rcvd_nsm_add,
						  MLD_VLAN_DCM),
				       CHECK_FLAG(vlan_node->rcvd_nsm_add,
						  MLD_VLAN_NSM));
			if (!CHECK_FLAG(vlan_node->rcvd_nsm_add, MLD_VLAN_DCM)) {
				mld_vlan_delete_confg(vlan_node);
				mld_del_vlan(vrfid, vlan_node);
			} else {
				UNSET_FLAG(vlan_node->rcvd_nsm_add,
					   MLD_VLAN_NSM);
				if (vlan_node->ivid)
					mld_portdb_delete_gvid(vlan_node->ivid);
				vlan_node->ivid = 0;
			}
		} else 
			L2MCD_LOG_INFO("%s vlan not found %d %d", __FUNCTION__,
				       gvid, ivid);
    }
    return;
}

/* Wrapper function to handle port add/del event */
int
mld_map_port_add_del(int vrfid, ifindex_t ifindex, int add, char *name, uint8_t type)
{
    unsigned int port;
	int retval;
    int rc = MLD_SUCCESS;

    if(add) {
		retval =  mld_l3_get_port_from_ifindex(ifindex, type);
		if ( -1 == retval)
		{
			L2MCD_LOG_INFO("%s Error: Invalid portnum ,vrf %d ifindex=0x%x, port 0x%x name=%s", __FUNCTION__, vrfid, ifindex, retval, name);
			return MLD_ERROR;

		}
		port = (unsigned int)retval;
		portdb_add_port_entry_to_tree(mld_portdb_tree, port,  vrfid, ifindex);
		portdb_add_ifname(name, strlen(name) + 1, port);
    } else {
		/* It is seen that name is sent as NULL from NSM. Better to delete using ifindex.*/
		retval = mld_l3_get_port_from_ifindex(ifindex, type);
		if ( -1 == retval)
		{
			L2MCD_LOG_INFO("%s Error: invalid portnum, vrf %d ifindex=0x%x, port 0x%x name=%s", __FUNCTION__, vrfid, ifindex, retval, name);
			return MLD_ERROR;

		}
		port = (unsigned int)retval;
		name = portdb_get_ifname_from_portindex(port);
		L2MCD_LOG_INFO("%s vrf %d port %d ifindex:%d type:%d  %s %d", __FUNCTION__, vrfid, port, ifindex, port, name, rc);
		if(name)
		{
			portdb_delete_ifname(name);
			 rc = portdb_remove_port_entry_from_tree(mld_portdb_tree, port);
		}
		else 
			L2MCD_LOG_INFO("%s vrf %d ifindex:0x%x type:%d port %d not present in portdb.", __FUNCTION__, vrfid, ifindex, type, port);
		
	}
    return rc;
}

time_t mld_get_current_monotime(void)
{
    struct timespec abs_time;

    clock_gettime(CLOCK_MONOTONIC, &abs_time);

    return abs_time.tv_sec;
}

int mld_proto_lmqi_set(uint32_t afi, uint32_t vid, uint32_t lmqi, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;
        UINT32 roundedlmqi = 0;

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport) {
		return MLD_SUCCESS;
	}

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_LAST_MEMBER_QUERY_INTERVAL)) {
		SET_FLAG(mcgrp_vport->flags,
			 MLD_IF_CFLAG_LAST_MEMBER_QUERY_INTERVAL);
		L2MCD_LOG_INFO
		    ("%s(): MLD_IF_CFLAG_LAST_MEMBER_QUERY_INTERVAL flag SET for"
		     "vlanid=%d", __FUNCTION__, vid);
	}

	/*lmq Interval received is in milliSec. So we have to roundoff the lmqi value */
        roundedlmqi = (lmqi < 1000) ? lmqi : MSEC2SECROUND (lmqi);

	if (mcgrp_vport->LMQ_interval != roundedlmqi)
	{
		mcgrp_vport->LMQ_interval = (UINT16) roundedlmqi;

		//this flag is used to start the 100 ms timer. 
		if (lmqi < 1000)
			mcgrp_vport->LMQ_100ms_enabled = TRUE;
		else 
			mcgrp_vport->LMQ_100ms_enabled = FALSE;
			
	}

	return MLD_SUCCESS;
}

int mld_proto_snooping_mrouter_if_set_api(mld_vlan_node_t * vlan_node,
				      int vrf_id, uint32_t port,
				      int enable, int afi)
{
	MCGRP_L3IF *mcgrp_vport;
	MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_id);
    uint16_t vport;
    MCGRP_PORT_ENTRY *mcgrp_pport = NULL;

   vport = mld_l3_get_port_from_ifindex(vlan_node->ifindex, vlan_node->type);

	mcgrp_vport =
	    IS_IGMP_CLASS(mld) ? gIgmp.port_list[vport] : gMld.port_list[vport];
	if (!mcgrp_vport) {
		L2MCD_LOG_INFO
		    ("%s.VRF%d: ERROR: Failed to get the vlan(%d) mcgrp_vport",
                     __FUNCTION__, mld->vrf_index, vlan_node->ivid);
       return (MLD_SUCCESS);
  }

    /*Need to test out this code*/
    if (is_virtual_port(mcgrp_vport->vir_port_id)) {
        mcgrp_pport =
            mcgrp_find_phy_port_entry(mld, mcgrp_vport, port);
        if (mcgrp_pport == NULL || !mcgrp_pport->is_up) {
            L2MCD_LOG_INFO("%s:%d Error: phy port 0x%x not found in vlan 0x%x or is not up",
                    __FUNCTION__, __LINE__,  port, mld_get_vlan_id(mcgrp_vport->vir_port_id));
            return(MLD_SUCCESS);
        }
       /* TBD Revisit this condiftion Srikanth */
    } else if (mcgrp_vport->vir_port_id == mcgrp_vport->phy_port_id) {
        mcgrp_pport =
            mcgrp_find_phy_port_entry(mld, mcgrp_vport,port);
        if (mcgrp_pport == NULL) {
            L2MCD_VLAN_LOG_ERR(mcgrp_vport->vir_port_id, "%s:%d mcgrp_pport NULL vir_port_id:%d phyport:%d port:%d", 
                    __FUNCTION__, __LINE__,mcgrp_vport->vir_port_id,mcgrp_vport->phy_port_id, port);
            return(MLD_SUCCESS);
        }
    } else {
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] phyport:%d", 
                __FUNCTION__, __LINE__,mcgrp_vport->vir_port_id,mcgrp_vport->phy_port_id);
        return(MLD_SUCCESS);
    }

	if (is_mld_snooping_enabled(mcgrp_vport, afi)) {
      if (enable) {
			mcgrp_add_router_port(mld, mcgrp_vport, port, TRUE,
					      MLD_PROTO_MROUTER,
					      DEFAULT_MROUTER_AGING_TIME, FALSE);
		} else {
			mcgrp_delete_router_port(mld, mcgrp_vport, port);
      }
  }
 
  return (MLD_SUCCESS);
}

void mcast_set_ip_addr(MADDR_ST * grp_addr, mcast_grp_addr_t * gaddr)
{

	if (gaddr->afi == MCAST_IPV4_AFI)
		mcast_set_ipv4_addr(grp_addr, gaddr->ip.ipv4_addr);
	else
		mcast_set_ipv6_addr(grp_addr,
				    (IPV6_ADDRESS *) & gaddr->ip.ipv6_addr);
}

// This funcion is invoked when there is a configuration change with
// regards to a port's membership in a multicast group.
// v4/v6 compliant
void
mcgrp_notify_l2_staticGroup_change(UINT32 afi,
                                      VRF_INDEX      vrf_index,
				   MADDR_ST * group_addr,
                                      PORT_ID        vir_port_id,
                                      //PORT_ID        phy_port_id,
                                      UINT32         phy_port_id,
                                      enum BOOLEAN   insert_flag)
{
    MCGRP_CLASS         *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index);
    UINT8                mcgrp_action;
    MCGRP_L3IF          *mcgrp_vport;
	MCGRP_STATIC_ENTRY *mcgrp_entry;

	if(!mcgrp) {
        L2MCD_VLAN_LOG_ERR(vir_port_id, "%s(%d) ERR:Multicast.CFG: Multicast is not enabled", __FUNCTION__, __LINE__);
		return;
	}

	if (insert_flag)
	{
		mcgrp_entry =
		    mcgrp_add_l2_staticGroup(mcgrp, vir_port_id, group_addr);
	}
	else
	{
		mcgrp_entry =
		    mcgrp_find_l2_staticGroup(mcgrp, vir_port_id, group_addr);
	}
	if (mcgrp_entry == NULL) {
		L2MCD_LOG_NOTICE(":%s:%d Failed to add static group virport:%d flag:%s",
				__FUNCTION__, __LINE__, vir_port_id, insert_flag);
        return;
    }
    L2MCD_VLAN_LOG_DEBUG(vir_port_id, "%s:%d vir_port:%d %s insert:%d",__FUNCTION__, __LINE__, vir_port_id,mcast_print_addr(group_addr), insert_flag);
	if (insert_flag) 
	{
       mld_sg_porttree_addport(&(mcgrp_entry->port_tree),phy_port_id);
    } 
	else 
	{
       mld_sg_porttree_delport(&(mcgrp_entry->port_tree),phy_port_id);
    }
	// Now if the port is enabled and UP, spread knowledge of this group.
	if ((mcgrp_vport =
	     IS_IGMP_CLASS(mcgrp) ? gIgmp.
	     port_list[vir_port_id] : gMld.port_list[vir_port_id]) == NULL) {
        L2MCD_LOG_NOTICE("%s port:%d vport NULL port:%d", __FUNCTION__, vir_port_id,phy_port_id);
		return;
	}
    // Join is equivalent to a EXCL none; Leave is equivalent to INCL none
    mcgrp_action = (insert_flag ? IS_EXCL : TO_INCL);
	mcgrp_update_l2_static_group(mcgrp, mcgrp_vport, mcgrp_entry,
				     mcgrp_action, phy_port_id);
	
	// Send the static group over mrouter ports on this vlan.
	mld_tx_static_report_leave_on_mrtr_port(mcgrp, &mcgrp_entry->group_address, mcgrp_vport, phy_port_id, insert_flag);
    l2mcd_system_group_entry_notify(&mcgrp_entry->group_address, NULL, vir_port_id, phy_port_id, TRUE, insert_flag);
	if (!insert_flag) {
		if (M_AVLL_FIRST(mcgrp_entry->port_tree) ==  NULL) {
			mcgrp_delete_l2_staticGroup(mcgrp, vir_port_id,
						    mcgrp_entry);
            dy_free(mcgrp_entry);
        }
	}
}
 
void mld_protocol_port_state_notify(mld_vlan_node_t * vlan_node, UINT32 afi,
			       MCGRP_CLASS * mld, UINT32 port,
			       enum BOOLEAN state_up)
{
    L2MCD_VLAN_LOG_INFO(vlan_node->gvid, "%s:%d:[vlan:%d] state: %d ifindex:%d [%s]", 
            FN,LN, vlan_node->ivid, state_up, port,mld_get_if_name_from_ifindex(port));
    
    if (vlan_node && mld_is_flag_set(vlan_node, afi, MLD_SNOOPING_ENABLED))
    {
        mcgrp_vport_state_notify(mld,
		    		 mld_l3_get_port_from_ifindex(vlan_node->ifindex,vlan_node->type),
			    										port, state_up);
    }

	if (state_up) {
		mld_static_grp_replay_confg(vlan_node, afi, mld, port);
    }
}

void mld_static_grp_deconfig_port(mld_vlan_node_t * vlan_node, uint32_t ifindex,
			     UINT32 port, uint8_t afi)
{
	
	struct list *list_head;
	struct listnode *list_node, *next_node;
	mld_l2_static_group_t  *static_grp;
	MADDR_ST     grp_addr;

	L2MCD_LOG_INFO("%s %s", mld_get_if_name_from_ifindex(port),
		       __FUNCTION__);

    /*
	 * Notify only for static group associated with VLAN
	 */

	list_head = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, FALSE);
	LIST_LOOP_DEL(list_head, static_grp, list_node, next_node) {

		if (!strcmp
		    (mld_get_if_name_from_ifindex(port),
		     static_grp->ifname)) {
			mcast_set_ip_addr(&grp_addr, &static_grp->grp_addr);
			mcgrp_notify_l2_staticGroup_change(afi,
							   MLD_DEFAULT_VRF_ID,
							   &grp_addr,
							   mld_l3_get_port_from_ifindex
							   (vlan_node->ifindex,vlan_node->type),
							   port, FALSE);
		}
	}

	return;
}

int mld_vlan_clear_group(uint32_t ifindex, MADDR_ST * grp_addr_clr,
		     int clr_grp_flag, uint8_t vlan_type)
{
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mld =
	    MCGRP_GET_INSTANCE_FROM_VRFINDEX(grp_addr_clr->afi, vrfid);
	PORT_ID vport;
	MCGRP_L3IF *mld_vport = NULL;
    MCGRP_STATIC_ENTRY  *mcgrp_st_entry = NULL;
	int ret = MLD_SUCCESS;

	//ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_id);
	vport = mld_l3_get_port_from_ifindex(ifindex,vlan_type);
	mld_vport =
	    IS_IGMP_CLASS(mld) ? gIgmp.port_list[vport] : gMld.port_list[vport];

	if (!mld_vport) {
		L2MCD_LOG_INFO("%s mld_vport NULL for ifindex =0x%x", __FUNCTION__, ifindex);
       return ret;
    }
	//Added to RC TR000613866 where mld_vport content is corrupted.
	L2MCD_LOG_INFO("%s(%d) ifindex:0x%x vport:%d %s ", FN, LN, ifindex, vport, mld_get_if_name_from_port(vport));
    ret = _mld_clear_group(mld, mld_vport, grp_addr_clr, clr_grp_flag);

    mcgrp_st_entry = mld_vport->static_mcgrp_list_head;

	for (; mcgrp_st_entry; mcgrp_st_entry = mcgrp_st_entry->next) {
        mcgrp_refresh_l2_static_group(mld, mcgrp_st_entry);
    }

    return ret;
}

void mld_intialize_with_def_values(mld_cfg_param_t * param)
{
    param->cfg_query_interval_time = CU_DFLT_IGMP_QUERY_INTERVAL;
    param->max_response_time       = CU_DFLT_IGMP_RESPONSE_TIME;
    param->group_membership_time   = CU_DFLT_IGMP_GROUP_MEMBERSHIP_TIME;
    param->older_host_present_time = CU_DFLT_IGMP_OLDER_HOST_PRESENT_TIME;
    param->cfg_robustness_var      = IGMP_DFLT_ROBUSTNESS;
    param->LMQ_interval            = CU_DFLT_LLQI_IN_MSEC;      /* milli seconds */
    param->LMQ_count               = param->cfg_robustness_var;
	param->start_up_query_interval = ((param->cfg_query_interval_time)/4); //param->LMQ_interval; 
    param->start_up_query_count    = param->cfg_robustness_var;
}

void mcgrp_delete_l2_staticGroup_if(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport)
{
	MCGRP_STATIC_ENTRY  *mcgrp_entry = mcgrp_vport->static_mcgrp_list_head, 
													*next_entry;

	while (mcgrp_entry) {
		next_entry = mcgrp_entry->next;
		
  		WheelTimer_DelElement(mcgrp->mcgrp_wtid,
				      &mcgrp_entry->
				      l2_static_grp_tmr.mcgrp_wte);
		if (mcgrp_entry) {
			linklist_delete_pointer((LINKLIST_TYPE **)
						&
						mcgrp_vport->static_mcgrp_list_head,
						(LINKLIST_TYPE *) mcgrp_entry);
		// if (mcgrp_entry->physical_mask)
      	//    dy_free(mcgrp_entry->physical_mask);
            mld_sg_delete_porttree(&(mcgrp_entry->port_tree));
			dy_free(mcgrp_entry);
  	}
		mcgrp_entry = next_entry;
	}
	return;
}

int mld_map_set_if_mld_mode(int ip_family, ifindex_t ifindex, int enable,
														VRF_INDEX vrf_index ,uint8_t type)
{
    int rc = MLD_SUCCESS;
    int port = mld_l3_get_port_from_ifindex(ifindex,type);
    /* Call the Foundry function now */
    mld_cu_set_if_mld_mode(ip_family, port, enable, vrf_index, ifindex, type);

    return rc;
}

/*
 * Retrive IP address from ve_portdb_tree
 */
uint32_t
ve_mld_portdb_get_port_lowest_ipv4_addr_from_list(uint32_t port_num)
{
	port_link_list_t *sptr_addr_entry = NULL;
	sptr_addr_entry = (port_link_list_t *)portdb_get_port_lowest_ipv4_addr_from_list(ve_mld_portdb_tree, port_num);
	if(sptr_addr_entry)
		return sptr_addr_entry->value.ipaddress;
	else
		return 0;
}

uint32_t mld_portdb_get_port_lowest_ipv4_addr_from_list(uint32_t port_num)
{
//	return (portdb_insert_addr_ipv4_list(mld_portdb_tree, port_num));
    port_link_list_t *sptr_addr_entry = NULL;
	sptr_addr_entry = (port_link_list_t *) (portdb_get_port_lowest_ipv4_addr_from_list(mld_portdb_tree, port_num));
	if(sptr_addr_entry)
		return sptr_addr_entry->value.ipaddress;
	else
		return 0;
}

/* clears total cache/ vlan specific/ grp specific cache */
int pims_clear_snoop_cache(int afi, mld_vid_t vlan_id, MADDR_ST *grp_addr_clr,uint8_t type)
{
	//VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	mld_vlan_node_t *vlan_node = NULL;
	struct listnode *node = NULL;
	int grp_filter = 0;
	//ifindex_t ifindex;
	//MCGRP_L3IF *mld_vport = NULL;
	L2MCD_LOG_INFO("%s(): PIMS: clear cache. afi %d, vlan %d", 
									__FUNCTION__, afi, vlan_id);	
	//MCGRP_CLASS *mld = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	
	if(vlan_id == 0 && !grp_addr_clr)   /* All vlans and groups */
	{
		LIST_LOOP(snooping_enabled_vlans[afi-1], vlan_node, node)   {
			if(vlan_node->flags[afi-1] & MLD_PIM_SNOOP_ENABLED)
			{
				vlan_id = vlan_node->ivid;
				pims_clear_group(afi, vlan_id, grp_addr_clr, grp_filter/*FALSE*/,
                                 vlan_node->type);
			}
		}
	}
	else if (vlan_id && !grp_addr_clr)
	{
		pims_clear_group(afi, vlan_id, grp_addr_clr, grp_filter/*FALSE*/,type);
	}
	
	return MLD_SUCCESS;
}

void pims_clear_statistics(int afi, mld_vid_t vlan_id, uint8_t type)
{
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;	
	mld_vlan_node_t *vlan_node = NULL;
	struct listnode *node = NULL;
	MCGRP_L3IF *mcgrp_vport = NULL;
	ifindex_t ifindex;
	PORT_ID vport;
	MCGRP_ENTRY *mcgrp_entry = NULL, *next_mcgrp_entry;
	
	L2MCD_LOG_INFO("%s(): PIMS: Clear PIM snoop statistics. afi %d, vlan %d",
												__FUNCTION__, afi, vlan_id);
	MCGRP_CLASS *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
	if(!mcgrp) {
		L2MCD_LOG_INFO("%s: mcgrp is NULL. afi %d, vlan %d", 
										__FUNCTION__, afi, vlan_id);
		return;
	}
	if(vlan_id)	/* clear for a specified vlan */
	{
        if(type == MLD_VLAN)
		    ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_id);
        else 
            ifindex = vlan_id;

		vport = mld_l3_get_port_from_ifindex(ifindex,type);
		mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vport] : gMld.port_list[vport];
		if (!mcgrp_vport) {
			L2MCD_LOG_INFO("%s: mcgrp_vport is NULL. afi %d, vlan %d", 
												__FUNCTION__, afi, vlan_id);
			return;
		}
	
		mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
		while (mcgrp_entry) {
			//next_mcgrp_entry = mcgrp_find_next_mbrshp(mcgrp_entry, mcgrp_mbrshp);
			next_mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree, mcgrp_entry->node);
			mcgrp_entry->pims_num_wg_joins_rcvd = 0;
			mcgrp_entry->pims_num_sg_joins_rcvd = 0;
			mcgrp_entry->pims_num_wg_prunes_rcvd = 0;
			mcgrp_entry->pims_num_sg_prunes_rcvd = 0;

			mcgrp_entry = next_mcgrp_entry;
		}
	}
	else /* All vlans */
	{
		LIST_LOOP(snooping_enabled_vlans[afi-1], vlan_node, node)   {
			if(vlan_node->flags[afi-1] & MLD_PIM_SNOOP_ENABLED)
			{
				//ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_node->ivid);
				ifindex = vlan_node->ifindex;
				vport = mld_l3_get_port_from_ifindex(ifindex,vlan_node->type);
				mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vport] : gMld.port_list[vport];
				if (!mcgrp_vport) 
					continue;
				mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
				while (mcgrp_entry) {
					//next_mcgrp_entry = mcgrp_find_next_mbrshp(mcgrp_entry, mcgrp_mbrshp);
					next_mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree, mcgrp_entry->node);
					mcgrp_entry->pims_num_wg_joins_rcvd = 0;
					mcgrp_entry->pims_num_sg_joins_rcvd = 0;
					mcgrp_entry->pims_num_wg_prunes_rcvd = 0;
					mcgrp_entry->pims_num_sg_prunes_rcvd = 0;

					mcgrp_entry = next_mcgrp_entry;
				}
			}
		}
	}

	return;
}

void mcgrp_delete_router_port(MCGRP_CLASS * mcgrp,
			 MCGRP_L3IF * mcgrp_vport, UINT32 phy_port_id)
{
    MCGRP_ROUTER_ENTRY  *mcgrp_rport = NULL, *mcgrp_prev_rport = NULL;
    MCGRP_PORT_ENTRY *mcgrp_pport = NULL;
	//MCGRP_ENTRY	*mcgrp_entry, *next_entry;
	mcgrp_rport = mcgrp_vport->rtr_port_list;
	//bool_t	wg_grp_del = FALSE;

	while (mcgrp_rport && (mcgrp_rport->phy_port_id != phy_port_id)) {
        mcgrp_prev_rport = mcgrp_rport;
        mcgrp_rport = mcgrp_rport->next;
    }

	if (!mcgrp_rport)
        return;

	L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id,"%s:%d:[vlan:%d] port id %d %p",  
		       FN,LN, mcgrp_vport->vir_port_id, phy_port_id,
		       &mcgrp_rport->mrtr_tmr.mcgrp_wte);
    
    if (!mcgrp_rport->is_static)
		WheelTimer_DelElement(mcgrp->mcgrp_wtid,
				      &mcgrp_rport->mrtr_tmr.mcgrp_wte);

	if (mcgrp_prev_rport)
    	mcgrp_prev_rport->next = mcgrp_rport->next;
	else
		mcgrp_vport->rtr_port_list = mcgrp_rport->next;

	// Notify to write to the redis AppDB
	l2mcd_system_mrouter_notify(mcgrp_vport->vir_port_id, phy_port_id, mcgrp_rport->is_static, 0);

    dy_free(mcgrp_rport);

	mcgrp_pport =
	    mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);

    if (mcgrp_pport)
        mcgrp_pport->snooping_mrouter_detected = FALSE;

}

MCGRP_ROUTER_ENTRY *
mcgrp_add_router_port(MCGRP_CLASS * mcgrp,
		      MCGRP_L3IF * mcgrp_vport,
              UINT32        phy_port_id,
		      BOOLEAN is_static, UINT16 type, UINT16 time, BOOLEAN is_mclag_remote)
{
    MCGRP_ROUTER_ENTRY  *new_mcgrp_rport;
    MCGRP_PORT_ENTRY *mcgrp_pport = NULL;

    if (!is_mclag_remote && l2mcd_is_peerlink(portdb_get_ifname_from_portindex(phy_port_id)))
    {
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] Discard mrouter learning on Peer link: port id %d", FN,LN, 
                mcgrp_vport->vir_port_id, phy_port_id);
        return NULL;
    }

	new_mcgrp_rport =
	    mcgrp_find_router_port_entry(mcgrp_vport, phy_port_id);
	if (new_mcgrp_rport) {
		if (new_mcgrp_rport->is_static)
			return NULL;

		if (new_mcgrp_rport->type != type) {
			new_mcgrp_rport->type = type;
		}
		if (new_mcgrp_rport->time != time) {
			new_mcgrp_rport->time = time;
		}

		if (!is_static) {
			if ((WheelTimerSuccess == WheelTimer_IsElementEnqueued
									(&new_mcgrp_rport->mrtr_tmr.mcgrp_wte))&&
				((type == MLD_PROTO_MROUTER || type == MLD_PIM_MROUTER))) {
					WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid,
							 &new_mcgrp_rport->mrtr_tmr.
							 mcgrp_wte,
							 (UINT32) time);
			}
		} else {
				new_mcgrp_rport->is_static = is_static;
				if (WheelTimerSuccess == WheelTimer_IsElementEnqueued
													(&new_mcgrp_rport->mrtr_tmr.mcgrp_wte))
					WheelTimer_DelElement(mcgrp->mcgrp_wtid,
						      &new_mcgrp_rport->mrtr_tmr.
						      mcgrp_wte);
		}
        return (new_mcgrp_rport);
    }

	L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] port id %d", FN,LN, 
													mcgrp_vport->vir_port_id, phy_port_id);

    // Alloc init appropriate data structures
	new_mcgrp_rport = dy_malloc_zero(sizeof (MCGRP_ROUTER_ENTRY));
	if (new_mcgrp_rport == NULL) {
		L2MCD_VLAN_LOG_ERR(mcgrp_vport->vir_port_id, "Failed to allocate MCGRP_PORT_ENTRY for %s vlan id %d port id %d", __FUNCTION__, 
													mcgrp_vport->vir_port_id, phy_port_id);
		return NULL;
	}
    
	new_mcgrp_rport->phy_port_id = phy_port_id;
	// Inherit the operating version from the virtual port's version
	new_mcgrp_rport->cfg_version  = MLD_NONE;
	new_mcgrp_rport->type = type;
	new_mcgrp_rport->time = time;
	// Prepend the port to the list of ports
	new_mcgrp_rport->next       = mcgrp_vport->rtr_port_list;
	mcgrp_vport->rtr_port_list  = new_mcgrp_rport;
    mcgrp_vport->rtr_port_list->uptime = mld_get_current_monotime();
    if (is_static)
       mcgrp_vport->rtr_port_list->is_static  = TRUE;
	else {
    	mcgrp_vport->rtr_port_list->is_static  = FALSE;
			// Add to the wheel timer.
			mcgrp_vport->rtr_port_list->mrtr_tmr.timer_type =
			    MCGRP_WTE_MROUTER;
	    mcgrp_vport->rtr_port_list->mrtr_tmr.mcgrp  = mcgrp;
			mcgrp_vport->rtr_port_list->mrtr_tmr.wte.
			    mrtr_port.mcgrp_vport = mcgrp_vport;
			mcgrp_vport->rtr_port_list->mrtr_tmr.wte.
			    mrtr_port.phy_port_id = phy_port_id;
		mcgrp_vport->rtr_port_list->mrtr_tmr.mcgrp_wte.data = 
													&new_mcgrp_rport->mrtr_tmr;
	    WheelTimer_AddElement(mcgrp->mcgrp_wtid,
					      &new_mcgrp_rport->
					      mrtr_tmr.mcgrp_wte,
					      (UINT32) time);
	}
	// Notify to write to the redis AppDB
	l2mcd_system_mrouter_notify(mcgrp_vport->vir_port_id, phy_port_id, is_static, 1);
	mcgrp_pport =   mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);

    if (mcgrp_pport)
	{
    	mcgrp_pport->snooping_mrouter_detected = TRUE;
	}
	return (MLD_SUCCESS);
}

//v4/v6 compliant
MCGRP_STATIC_ENTRY * mcgrp_add_l2_staticGroup(MCGRP_CLASS * mcgrp,
			 PORT_ID port_id, MADDR_ST * group_addr)
{
    MCGRP_STATIC_ENTRY  *mcgrp_entry;
    MCGRP_L3IF          *mcgrp_vport;

	mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[port_id] :
														gMld.port_list[port_id];

    mcgrp_entry = mcgrp_find_l2_staticGroup(mcgrp, port_id, group_addr);

	if (mcgrp_entry != NULL) {
        if (WheelTimerSuccess !=
			    WheelTimer_IsElementEnqueued
			    (&mcgrp_entry->l2_static_grp_tmr.mcgrp_wte)) {
				mcgrp_entry->l2_static_grp_tmr.timer_type =
				    MCGRP_WTE_L2_STATIC;
				mcgrp_entry->l2_static_grp_tmr.mcgrp = mcgrp;
				mcgrp_entry->l2_static_grp_tmr.
				    wte.l2_static_grp = mcgrp_entry;
				mcgrp_entry->l2_static_grp_tmr.mcgrp_wte.data =
				    &mcgrp_entry->l2_static_grp_tmr;

				WheelTimer_AddElement(mcgrp->mcgrp_wtid,
						      &mcgrp_entry->
						      l2_static_grp_tmr.mcgrp_wte,
						      mcgrp_vport->query_interval_time);
			}
        return mcgrp_entry;
    }

    /* can't find it */
	mcgrp_entry =
	    (MCGRP_STATIC_ENTRY *) dy_malloc(sizeof (MCGRP_STATIC_ENTRY));
	if (mcgrp_entry) {

        mcgrp_entry->port_num = port_id;

        mcast_set_addr(&mcgrp_entry->group_address, group_addr);
        mcgrp_entry->next = mcgrp_vport->static_mcgrp_list_head;
        mcgrp_vport->static_mcgrp_list_head = mcgrp_entry;
	    static int ifindex_offset= M_AVLL_OFFSETOF(sg_port_t, ifindex);
        mcgrp_entry->port_tree=L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &ifindex_offset, NULL);

        // Add to the wheel timer.
        {
			mcgrp_entry->l2_static_grp_tmr.timer_type =
			    MCGRP_WTE_L2_STATIC;
			mcgrp_entry->l2_static_grp_tmr.mcgrp = mcgrp;
			mcgrp_entry->l2_static_grp_tmr.wte.l2_static_grp =
			    mcgrp_entry;
			mcgrp_entry->l2_static_grp_tmr.mcgrp_wte.data =
			    &mcgrp_entry->l2_static_grp_tmr;

			WheelTimer_AddElement(mcgrp->mcgrp_wtid,
					      &mcgrp_entry->l2_static_grp_tmr.
					      mcgrp_wte,
					      mcgrp_vport->query_interval_time);
		}
	}
	return mcgrp_entry;
}

int mld_sg_porttree_addport(L2MCD_AVL_TREE *port_tree, uint32_t port)
{
	sg_port_t *sg_port;
   	sg_port = calloc(1,sizeof(sg_port_t));
    if(sg_port == NULL) {
		L2MCD_LOG_ERR("%s alloc sg_port fail port:0x%x", __FUNCTION__, port);
       	return(-1);
    }
	M_AVLL_INIT_NODE(sg_port->node); 
    sg_port->ifindex = port;
    if (!M_AVLL_INSERT(*port_tree,sg_port)){
		L2MCD_LOG_NOTICE("%s insert sg_port to avl fail port:0x%x",__FUNCTION__, port);
       	free(sg_port);
       	return (-1);
    }
    return 0;
}

void mcgrp_update_l2_static_group(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport,
			     MCGRP_STATIC_ENTRY * mcgrp_entry, UINT8 mcgrp_action, UINT32 target_port)
{
    UINT32             phy_port_id = target_port;
    MCGRP_PORT_ENTRY  *mcgrp_pport = NULL;
    MADDR_ST           addr;
    UINT8              v3_action = mcgrp_action;
    UINT32            *src_list  = NULL;  //No sources
    UINT16             num_srcs  = 0;
    MADDR_ST           group_addr;
    UINT8              version  = 0;

    mcast_set_addr(&group_addr, &mcgrp_entry->group_address);

	if (is_virtual_port(mcgrp_vport->vir_port_id)) {
		mcgrp_pport =
		    mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
		if (mcgrp_pport == NULL || !mcgrp_pport->is_up) {
			return;
		}
	} else if (mcgrp_vport->vir_port_id == mcgrp_vport->phy_port_id) {
	    mcgrp_pport =
		         mcgrp_find_phy_port_entry(mcgrp, mcgrp_vport, phy_port_id);
		if (mcgrp_pport == NULL)
		    return;
	} else {
		return;
	}

	L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d]  PhyPort:%x Up:%d", FN,LN, mcgrp_vport->vir_port_id, mcgrp_vport->phy_port_id, mcgrp_pport->is_up);

	if (IS_IGMP_CLASS(mcgrp)) {
		version = ((mcgrp_pport->oper_version >= IGMP_VERSION_2) 
							? IGMP_STATIC_VER2  : IGMP_STATIC_VER1);
		mcast_set_ipv4_addr(&addr, ip_get_lowest_ip_address_on_port
												(mcgrp_vport->vir_port_id, mcgrp_vport->type));
		//Port mode IGMPv3 and IGMPv2 static group configured,
		//below would perfom SSM MAP  IGMPv2 convert to mapped source -> IGMPv3
		if (igmp_update_ssm_parameters(mcgrp, &group_addr, &version,
					       mcgrp_vport->vir_port_id,
					       phy_port_id, &v3_action,
						&num_srcs, &src_list) == FALSE)
		{
			MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, "%s(%d) PIM SSM group:%s ssm-map failed\n",
				FN, LN, mcast_print_addr(&group_addr));
			//TODO: Check all cases of non SSM, before returning from configuration step,
			//IGMP FSM will check all conditions and ignore report. 
			//return;	
		}
	} else {
        //MLD
	}

	if (!mcgrp_pport->is_up)
		return;
	
	mcgrp_update_group_address_table(mcgrp, mcgrp_vport->vir_port_id, phy_port_id, &mcgrp_entry->group_address, &addr,	// use intf's addr as client source  
					 v3_action, version, num_srcs, (void *) src_list);	/* No sources */
}

//v4/v6 compliant
MCGRP_STATIC_ENTRY * mcgrp_find_l2_staticGroup(MCGRP_CLASS * mcgrp,
			  PORT_ID port_id, MADDR_ST * group_addr)
{
    MCGRP_STATIC_ENTRY *mcgrp_entry;
    MCGRP_L3IF          *mcgrp_vport;

	mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[port_id] : 
										gMld.port_list[port_id];

    mcgrp_entry = mcgrp_vport->static_mcgrp_list_head;

    //while (mcgrp_entry && (mcast_cmp_addr(&mcgrp_entry->group_address, group_addr) <= 0))
	while (mcgrp_entry) {
        if ((mcgrp_entry->port_num == port_id) &&
		    (mcast_cmp_addr(&mcgrp_entry->group_address, group_addr) ==
		     0)) {
            return mcgrp_entry;
        }
        mcgrp_entry = mcgrp_entry->next;
    }

    return NULL;
}

int mld_sg_port_cmp_cb (void *keya,void *keyb)
{
	return (*(UINT32 *)keya - *(UINT32 *) keyb);
}
void mld_static_grp_replay_confg(mld_vlan_node_t * vlan_node, int afi,
			    MCGRP_CLASS * mld, uint32_t phy_port)
{
	MADDR_ST     grp_addr;
	struct list *s_list;
    struct listnode *list_node;
	mld_l2_static_group_t  *static_grp;
  char *if_name = NULL;
	s_list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, FALSE);
    if_name =  mld_get_if_name_from_ifindex(phy_port);
	LIST_LOOP(s_list, static_grp, list_node) {
	  L2MCD_LOG_INFO("%s %d %x %s %s", __FUNCTION__, phy_port,
			       //mld_get_port_ifindex(phy_port),
			       if_name,
			       static_grp->ifname,
			    //   portdb_get_ifname_from_portindex(phy_port));
			       mld_get_if_name_from_ifindex(phy_port));
		if (strncmp
		    (static_grp->ifname,
		   //  portdb_get_ifname_from_portindex(phy_port),
		     if_name,
		     INTERFACE_NAMSIZ) == 0) {
			L2MCD_LOG_INFO("in side %s %s", static_grp->ifname,  
				    //   portdb_get_ifname_from_portindex (phy_port));
				       if_name);
			mcast_set_ip_addr(&grp_addr, &static_grp->grp_addr);
			mcgrp_notify_l2_staticGroup_change(afi,
							   MLD_DEFAULT_VRF_ID,
							   &grp_addr,
							   mld_l3_get_port_from_ifindex
							   (vlan_node->ifindex,vlan_node->type),
							   phy_port, TRUE);
		}
	}

}

int _mld_clear_group(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport,
		 MADDR_ST * grp_addr_clr, int clr_grp_flag)
{
	if (!mcgrp || !mcgrp_vport) {
		L2MCD_LOG_INFO("%s(): Arguments NULL", __FUNCTION__);
		return (MLD_SUCCESS);
	}
	MCGRP_ENTRY         *mcgrp_entry = NULL, *next_entry = NULL;
	MCGRP_MBRSHP        *mcgrp_mbrshp = NULL, *next_mcgrp_mbrshp = NULL;
	mcast_grp_addr_t gaddr;
    uint32_t  afi = (IS_IGMP_CLASS(mcgrp) ? MCAST_IPV4_AFI:MCAST_IPV6_AFI);
  	mcast_grp_addr_t *grp_addr = NULL;
	MADDR_ST source_address;
 
	grp_addr =(mcast_grp_addr_t *) calloc (1, sizeof(mcast_grp_addr_t));
	if(grp_addr == NULL) {
		L2MCD_LOG_INFO("%s(): grp_addr alloc failed. ", __FUNCTION__);
		return (MLD_SUCCESS);
	}
	
	if(grp_addr_clr)
		mcast_set_address(grp_addr, grp_addr_clr);

	mcast_init_addr(&source_address, afi, MADDR_GET_FULL_PLEN(afi));
	mcast_set_addr_any(&source_address);

	mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
	while (mcgrp_entry) {
		next_entry =
		    (MCGRP_ENTRY *) M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree,
						mcgrp_entry->node);

		if (clr_grp_flag
		    &&
		    (!(((mcast_cmp_addr
			(&mcgrp_entry->group_address, grp_addr_clr)) == 0)))) {
			mcgrp_entry = next_entry;
			continue;
		}

		mcgrp_mbrshp = mcgrp_find_first_mbrshp(mcgrp_entry);

		while (mcgrp_mbrshp) {
			next_mcgrp_mbrshp =
			    mcgrp_find_next_mbrshp(mcgrp_entry, mcgrp_mbrshp);
			//ifindex = mld_get_port_ifindex(mcgrp_mbrshp->phy_port_id);
			if (is_mld_snooping_enabled(mcgrp_vport, afi)) {
				if (!received_clear_grp_notify) {
					mld_send_l2mcd_sync_group_upd(
							    &mcgrp_entry->group_address,
							    mcgrp_vport->vir_port_id,
							    0, 0, 1,
							    mcgrp_mbrshp->phy_port_id,
							    &source_address, 0);
				}
				mcast_set_address(&gaddr, &mcgrp_entry->group_address);
			}

			mcast_set_address(grp_addr, &mcgrp_entry->group_address);
            if (mcgrp_vport) {

				if(mcgrp_vport->oper_version == IGMP_VERSION_3)
				{
		
					if (mcgrp_mbrshp->filter_mode == FILT_INCL)
					{
						MCGRP_SOURCE* p_src = mcgrp_mbrshp->src_list[FILT_INCL];
						for (; p_src; p_src = p_src->next)
						{
							L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id,"%s:%d:[vlan:%d]  Remove: S:%s GA:%s port:%d",
							       __FUNCTION__, __LINE__, mcgrp_vport->vir_port_id, mcast_print_addr(&p_src->src_addr), 
								   mcast_print_addr(&mcgrp_entry->group_address), mcgrp_mbrshp->phy_port_id);
							l2mcd_system_group_entry_notify(&mcgrp_entry->group_address, &p_src->src_addr,
					              mcgrp_vport->vir_port_id, mcgrp_mbrshp->phy_port_id, 0, FALSE);
						}
					}
				}
				else
				{
					L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id,"%s:%d:[vlan:%d]  Remove: S:%s GA:%s port:%d",
							       __FUNCTION__, __LINE__, mcgrp_vport->vir_port_id, mcast_print_addr(&source_address), 
								   mcast_print_addr(&mcgrp_entry->group_address), mcgrp_mbrshp->phy_port_id);
					l2mcd_system_group_entry_notify(&mcgrp_entry->group_address, &source_address,
					         mcgrp_vport->vir_port_id, mcgrp_mbrshp->phy_port_id, 0, FALSE);
				}
				
			}

			/* Remove this port from the group membership */
			mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mcgrp_mbrshp);
			/* If no member ports left in this group, remove this group from this virtual port */
			if (mcgrp_entry->num_mbr_ports == 0) {
				MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV4_AFI, 
					"%s(%d) No member ports left, remove this group from vir port. ", FN, LN);
				mcgrp_notify_vif_del(mcgrp,
						     &mcgrp_entry->group_address,
						     mcgrp_vport, mcgrp_entry, TRUE);
				mcgrp_destroy_group_addr(mcgrp, mcgrp_vport,
							 mcgrp_entry);
			}
				
			mcgrp_mbrshp = next_mcgrp_mbrshp;
		}

		mcgrp_entry = next_entry;
	}
	if(grp_addr)
		free(grp_addr);
	return (MLD_SUCCESS);
}

// This function is called periodically to refresh the static group memberships
// //v4/v6 compliant
void mcgrp_refresh_l2_static_group(MCGRP_CLASS * mcgrp,
			      MCGRP_STATIC_ENTRY * mcgrp_entry)
{
	if (!mcgrp || !mcgrp_entry) {
		return;
	}
    UINT16  vir_port_id;
    UINT32 phy_port_id;
    MCGRP_L3IF *mcgrp_vport;
	sg_port_t *sg_port;
    MADDR_ST            *group_address = NULL;
    MADDR_ST             addr;
    UINT8                version = 0;
    UINT8                igmp_action = 0;
    UINT16               num_srcs = 0;
    UINT32              *src_list = NULL;

    group_address = &mcgrp_entry->group_address;

    vir_port_id = mcgrp_entry->port_num;

    mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] :
																gMld.port_list[vir_port_id];

	if (mcgrp_vport == NULL || (!mcgrp_vport->is_up)) {
		if (mcgrp_vport == NULL) {
                return;
        }
    }
    
    /* Notify mcgrp static group membership for every port in port mask */
    for(sg_port = M_AVLL_FIRST(mcgrp_entry->port_tree);
        sg_port;
        sg_port = M_AVLL_NEXT(mcgrp_entry->port_tree,sg_port->node))
    {

        MCGRP_MBRSHP      *mcgrp_mbrshp = NULL;
		phy_port_id = sg_port->ifindex;
         // On update, the PIM/DVMRP functions get the port# from this data struct
        mcgrp_mbrshp = mcgrp_find_mbrshp_entry_for_grpaddr(mcgrp,
                                                           group_address,
                                                           vir_port_id,
                                                           phy_port_id);
		if(mcgrp_mbrshp) {
			MLD_LOG(MLD_LOGLEVEL7, MLD_IP_IPV4_AFI, 
				"%s(%d)  grp:%s phy_port_id:%d  \n", FN, LN, 
				mcast_print_addr(group_address), mcgrp_mbrshp->phy_port_id);

		}
        version = ((mcgrp_vport->oper_version >= IGMP_VERSION_2) ?
                                                   IGMP_STATIC_VER2 : IGMP_STATIC_VER1);

		if (IS_IGMP_CLASS(mcgrp)) {
			mcast_set_ipv4_addr(&addr,
					    ip_get_lowest_ip_address_on_port(vir_port_id, mcgrp_vport->type));
			igmp_action = IS_EXCL;
			//Port mode IGMPv3 and IGMPv2 static group configured,
			//below would perfom SSM MAP  IGMPv2 convert to mapped source -> IGMPv3
			if (igmp_update_ssm_parameters
			    (mcgrp, group_address, &version, vir_port_id,
			     phy_port_id, &igmp_action, &num_srcs,
														&src_list) == FALSE)
			{
				MLD_LOG(MLD_LOGLEVEL9, MLD_IP_IPV4_AFI, "%s(%d) PIM SSM group:%s ssm-map failed\n",
					FN, LN, mcast_print_addr(group_address));
			}
		} else {
            //MLD
        }
		mcgrp_update_group_address_table(mcgrp, vir_port_id, phy_port_id, group_address, &addr,	// use intf's addr as client source
						 igmp_action, version, num_srcs, (void *) src_list);	/* No sources */
		//Send the static group over mrouter ports
		if (mcgrp_mbrshp && mcgrp_mbrshp->static_mmbr)
		{
			mld_tx_static_report_leave_on_mrtr_port(mcgrp, group_address, mcgrp_vport,
				mcgrp_mbrshp->phy_port_id, TRUE);
		}

    }

    if (WheelTimerSuccess == WheelTimer_IsElementEnqueued
							(&mcgrp_entry->l2_static_grp_tmr.mcgrp_wte))
        WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid,
					 &mcgrp_entry->
					 l2_static_grp_tmr.mcgrp_wte, (UINT32)
					 mcgrp_vport->query_interval_time);
	else
	{
		mcgrp_entry->l2_static_grp_tmr.timer_type =
                MCGRP_WTE_L2_STATIC;
        mcgrp_entry->l2_static_grp_tmr.mcgrp = mcgrp;
        mcgrp_entry->l2_static_grp_tmr.wte.l2_static_grp =
                mcgrp_entry;
        mcgrp_entry->l2_static_grp_tmr.mcgrp_wte.data =
                &mcgrp_entry->l2_static_grp_tmr;
		WheelTimer_AddElement(mcgrp->mcgrp_wtid,
				      &mcgrp_entry->l2_static_grp_tmr.mcgrp_wte,
				      (UINT32)
				      mcgrp_vport->query_interval_time);
	}
}

void mld_sg_delete_porttree(L2MCD_AVL_TREE *port_tree)
{
    sg_port_t *sg_port,*next_sg_port;

	sg_port = M_AVLL_FIRST(*port_tree);
    while(sg_port) {
		next_sg_port = M_AVLL_NEXT(*port_tree, sg_port->node); 
		M_AVLL_DELETE(*port_tree,sg_port);
		free(sg_port);
      	sg_port = next_sg_port;
    }
    return;
}

/* Wrapper function to handle setting interface PIM mode CLI event */
void mld_cu_set_if_mld_mode(int ip_family, UINT16 port, int enable,
							VRF_INDEX vrf_index, ifindex_t ifindex, uint8_t type)
{
	MCGRP_CLASS   *mcgrp;
	mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(ip_family, vrf_index);

	if (enable == ENABLE) {
		mcgrp_create_l3intf(mcgrp, (UINT16) port);
		L2MCD_LOG_INFO("%s(%d) created l3intf for port: %d ifindex 0x %x State:%d", 
			__FUNCTION__, __LINE__, port, ifindex, IP6_PORT_IS_UP(port));

		if (IS_IP6_PORT_DB_VALID(port)) {
			// If IP interface is Up, process "interface-Up" event.
			if (IP6_PORT_IS_UP(port)) {
				// Notify MLD to start
				mcgrp_port_state_notify(ip_family, vrf_index,
							port, TRUE);
			}
		}
	} else {
			 	// Notify IGMP/MLD to stop
        mcgrp_port_state_notify(ip_family, vrf_index, port, FALSE);      
        mcgrp_delete_l3intf(mcgrp, port);
	}
}

int mld_port_exist_in_port_db(uint16_t port_num)
{
	if (!portdb_find_port_entry(mld_portdb_tree, port_num))
        return (FALSE);

	return (TRUE);
}


void mcgrp_reset_mld_stats(MCGRP_CLASS * mld, ifindex_t ifindex,uint8_t vlan_type)
{
	PORT_ID vport;
	MLD_STATS *mstats = NULL;
	IGMP_STATS *istats = NULL;

	if (!mld)
		return;

    vport = mld_l3_get_port_from_ifindex(ifindex,vlan_type);

    if (IS_IGMP_CLASS(mld)) {
	    istats = &mld->igmp_stats[vport];
		/*Clear stats */
		if (istats) {
			memset(istats, 0, sizeof (IGMP_STATS));
		}
	}
	else {
		mstats = &mld->mld_stats[vport];
		/*clear stats */
		if (mstats) {
			memset(mstats, 0, sizeof (MLD_STATS));
		}
	}

}

void mld_del_vlan(int vrfid, mld_vlan_node_t * vlan_node)
{
	//uint8_t afi;

	//for (afi = 1; afi <= MCAST_AFI_MAX; afi++)
	//	mld_vcs_delete_local_vlan(vlan_node->gvid, afi);
	mld_vdb_vlan_del(mld_vlan_get_db(), vlan_node->gvid,vlan_node->type);
}

/* Can Clear all groups of a vlan or a single group as well */
int pims_clear_group(int afi, mld_vid_t vlan_id,
					MADDR_ST *grp_addr_clr, int grp_filter, uint8_t type )
{
	VRF_INDEX vrfid = MLD_DEFAULT_VRF_ID;
	ifindex_t ifindex;
	MCGRP_L3IF *mcgrp_vport = NULL;
	MCGRP_ENTRY *mcgrp_entry = NULL;
	MCGRP_ENTRY * next_entry = NULL;
	MCGRP_MBRSHP *mcgrp_mbrshp, *next_mcgrp_mbrshp;
	PORT_ID vport;
	MCGRP_SOURCE *src_entry, *next_src;
	uint32_t phy_ifindex  = 0, ivid = 0;
	uint8_t v1_mbr = 0, v2_mbr = 0, v3_mbr = 0;
	uint8_t del_mbr_req = 0;	

	L2MCD_LOG_INFO("%s(): PIMS: afi %d, vlan_id %d", __FUNCTION__, afi, vlan_id);
	MCGRP_CLASS *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrfid);
    if (type == MLD_VLAN)
	{
		ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_id);
	}
    else
	{
        ifindex = vlan_id; 
	}

	vport = mld_l3_get_port_from_ifindex(ifindex, type);
	mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vport] : gMld.port_list[vport];
	if (!mcgrp_vport) {
		return FALSE;
	}

	mcgrp_entry = (MCGRP_ENTRY *) M_AVLL_FIRST(mcgrp_vport->sptr_grp_tree);
	while (mcgrp_entry) {
		next_entry = (MCGRP_ENTRY *) M_AVLL_NEXT(mcgrp_vport->sptr_grp_tree,
			mcgrp_entry->node);
		/* This check is needed when we support grp specific filter */
		if(grp_filter &&
			(!((mcast_cmp_addr(&mcgrp_entry->group_address, grp_addr_clr)) == 0))) {
			mcgrp_entry = next_entry;
			continue;
		}

		mcgrp_mbrshp = mcgrp_find_first_mbrshp(mcgrp_entry);
		while (mcgrp_mbrshp) 
		{
			v1_mbr = 0; v2_mbr = 0; v3_mbr = 0; del_mbr_req = 0;
			mld_is_snoop_mbrship_present(mcgrp_mbrshp, &v1_mbr, &v2_mbr, &v3_mbr);
			next_mcgrp_mbrshp = mcgrp_find_next_mbrshp(mcgrp_entry, mcgrp_mbrshp);
			src_entry = mcgrp_mbrshp->pims_src_list;
			while (src_entry) 
			{
				next_src = src_entry->next;
				/* Prepare the list of port to delete for this (S,G,V)
				 * entry and send port delelete to mcastss
				 */
				l2mcd_sync_inherit_and_send_rte(mcgrp, mcgrp_vport, mcgrp_entry, 
					mcgrp_mbrshp->phy_port_id, &src_entry->src_addr, 0 /*del*/);
				src_entry = next_src;
			}
			/* This port can have MLD/IGMP Join as well */
			if(!v2_mbr)
			{
				//Send port del for *GV to mcastss if NO v2 join
				//phy_ifindex = mld_get_port_ifindex(mcgrp_mbrshp->phy_port_id);
				phy_ifindex = mcgrp_mbrshp->phy_port_id;
    			ivid = mld_portdb_get_ivid_from_gvid(vlan_id,type);
				/*
				 * This port could be inherited to the SGV entries on other
				 * ports. So we need to delete this inherited port 
				 */
				l2mcd_sync_pims_upd_inherit_ports_to_sg(mcgrp_entry, mcgrp_mbrshp, vlan_id, 
					phy_ifindex, mcgrp_entry->group_address.afi, FALSE/*del*/,ivid);

				if(!v3_mbr)
					del_mbr_req = 1;
			}
			/* Clear flags related to PIM Snooping */
			mcgrp_mbrshp->pims_mbr_flags &= ~PIMS_WG_MBR_PORT;

			/* Now remove PIM snp source list and clear the SG flags on this mbr*/
			if(mcgrp_mbrshp->pims_src_list)
				mcgrp_pims_destroy_src_list(mcgrp, mcgrp_mbrshp);
			mcgrp_mbrshp->pims_mbr_flags &= ~PIMS_SG_MBR_PORT;
			if(del_mbr_req)
				mcgrp_destroy_mbrshp_entry(mcgrp, mcgrp_entry, mcgrp_mbrshp);
			mcgrp_mbrshp = next_mcgrp_mbrshp;
		}

		mcgrp_entry->pims_num_wg_join_ports = 0;
		mcgrp_entry->pims_num_sg_join_ports = 0;

		if (mcgrp_entry->num_mbr_ports == 0)
		{
			MLD_LOG(MLD_LOGLEVEL8, MLD_IP_IPV4_AFI, 
				"%s(%d): num_mbr_ports is 0 for Grp:%s, vlan:%d", FN, LN, 
				mcast_print_addr(&mcgrp_entry->group_address), vlan_id);
			mcgrp_destroy_group_addr(mcgrp, mcgrp_vport, mcgrp_entry);
		}
		mcgrp_entry = next_entry;
	}

	return MLD_SUCCESS;
}					

//v4/v6 compliant
MCGRP_ROUTER_ENTRY * mcgrp_find_router_port_entry(MCGRP_L3IF * mcgrp_vport, UINT32 phy_port_id)
{
	MCGRP_ROUTER_ENTRY *mcgrp_rport = NULL;

	if (!mcgrp_vport)
		return NULL;

	mcgrp_rport = mcgrp_vport->rtr_port_list;

	while (mcgrp_rport && (mcgrp_rport->phy_port_id != phy_port_id))
		mcgrp_rport = mcgrp_rport->next;

	return mcgrp_rport;
}

int mld_sg_porttree_delport(L2MCD_AVL_TREE *port_tree, uint32_t port)
{
	sg_port_t *sg_port;
	sg_port = M_AVLL_FIND(*port_tree, &port);
	if (sg_port) 
	{
		M_AVLL_DELETE(*port_tree,sg_port);
		free(sg_port);
	}
    return 0;
}

//v4/v6 compliant
void mcgrp_delete_l2_staticGroup(MCGRP_CLASS * mcgrp,
			    PORT_ID port_id, MCGRP_STATIC_ENTRY * mcgrp_entry)
{
	MCGRP_L3IF *mcgrp_vport;

	mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[port_id] :
	    gMld.port_list[port_id];
	WheelTimer_DelElement(mcgrp->mcgrp_wtid,
			      &mcgrp_entry->l2_static_grp_tmr.mcgrp_wte);
	if (mcgrp_entry) {
		linklist_delete_pointer((LINKLIST_TYPE **)
					& mcgrp_vport->static_mcgrp_list_head,
					(LINKLIST_TYPE *) mcgrp_entry);
		//if (mcgrp_entry->physical_mask)
		//	dy_free(mcgrp_entry->physical_mask);
         mld_sg_delete_porttree(&(mcgrp_entry->port_tree));
	}
	return;
}

void mcgrp_start_igmp_querier(MCGRP_CLASS * mcgrp,
		                      MCGRP_L3IF * mcgrp_vport, uint8_t afi, BOOLEAN flag)
{
	   //mld_vid_t gvid = 0;

       if (mcgrp == NULL || mcgrp_vport == NULL) {
           L2MCD_LOG_INFO("%s: returning mcgrp/mcgrp_vport is NULL",
	                      __FUNCTION__);
           return;
       }

       //gvid = mld_get_vlan_id(mcgrp_vport->vir_port_id);
       if ((is_mld_snooping_enabled(mcgrp_vport, afi)
	        && is_mld_snooping_querier_enabled(mcgrp_vport)) ||
	    	is_mld_l3_configured(mcgrp_vport)) {
			if (flag) {
			   mcgrp_vport_start_querier_process(mcgrp, mcgrp_vport);
			   L2MCD_LOG_INFO("%s(): Start querier process", __FUNCTION__);
		    }	
	   }
}

void mld_snoop_clear_on_version_change(uint32_t vid, int afi, uint8_t type)
{
	MADDR_ST grp_addr_clr;
	int clr_grp_flag = 0;
	uint16_t ivid = 0;
	afi = MCAST_IPV4_AFI;

    grp_addr_clr.afi = afi;
	if(type == MLD_BD)	
		ivid = mld_portdb_get_ivid_from_gvid(vid,type);
    else
		ivid = vid;
	mld_iterate_vlan_group_clear(ivid, &grp_addr_clr, clr_grp_flag,type);

	return;
}

int mld_proto_query_interval_set(uint32_t afi, uint32_t vid, mld_vid_t gvid,
			     uint32_t query_interval, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;
	MCGRP_CLASS *mcgrp = 
		MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, MLD_DEFAULT_VRF_ID);
	UINT16 send_port = 0;
	uint32_t ifindex = 0;

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	//uint32_t ipv4_any = 0;

	if (!mcgrp_vport) {
      return MLD_SUCCESS;
    }

    /* Validate Query Interval to be > Query Response Interval */
	if (query_interval <= mcgrp_vport->max_response_time) {
		L2MCD_LOG_INFO
		    ("%s(): query interval time is lesser than query response"
						"time %d %u", __FUNCTION__, vid, query_interval);
      return  MLD_CLI_ERR_QI_LE_QRI;
    }

	if (!CHECK_FLAG(mcgrp_vport->flags, MLD_IF_CFLAG_QUERY_INTERVAL)) {
		SET_FLAG(mcgrp_vport->flags, MLD_IF_CFLAG_QUERY_INTERVAL);
		L2MCD_LOG_INFO("%s(): MLD_IF_CFLAG_QUERY_INTERVAL flag SET for"
			       "vlanid=%d", __FUNCTION__, vid);
    }

    /* Set query interval */
	if (mcgrp_vport->cfg_query_interval_time != query_interval) {
		mcgrp_vport->cfg_query_interval_time = (UINT16) query_interval;
		mcgrp_vport->query_interval_time = (UINT16) query_interval;
    }

    	/* Calculate Group membership timer */
	mcgrp_vport->group_membership_time =
	    GROUP_MEMBERSHIP_INTERVAL(mcgrp_vport);

	/*Recalculate OQI if not configured */
	mcgrp_vport->older_host_present_time =
	    OTHER_QUERIER_PRESENT_INTERVAL(mcgrp_vport);

    if (!CHECK_FLAG(mcgrp_vport->flags, MLD_IF_CFG_SNOOP_STARTUP_QUERY_INTERVAL)){
        mcgrp_vport->start_up_query_interval = query_interval/4;
    }

	ifindex = portdb_get_port_ifindex(mld_portdb_tree, mcgrp_vport->vir_port_id);


    if(l2mcd_ifindex_is_physical(ifindex)) 
        send_port = mcgrp_vport->vir_port_id;
	
    else
        send_port = PORT_INDEX_INVALID;

    {
		if ((is_mld_snooping_enabled(mcgrp_vport, afi)
			&& is_mld_snooping_querier_enabled(mcgrp_vport))
			|| is_mld_l3_configured(mcgrp_vport)) {
			/* Send a GQ immediately after change in query interval */
			if (afi == MCAST_IPV4_AFI)
			{
				igmp_send_general_query(mcgrp, mcgrp_vport->vir_port_id, send_port,
						               (UINT8) mcgrp_vport->oper_version, 0,
									   mcgrp_vport->max_response_time * 10);
			}
			else 
			{
				return MLD_SUCCESS;
                //MLD
			}
		}
		if (WheelTimerSuccess ==
		    WheelTimer_IsElementEnqueued(&mcgrp_vport->
						 vport_tmr.mcgrp_wte)) {

			WheelTimer_ReTimeElement(mcgrp->mcgrp_wtid,
						 &mcgrp_vport->
						 vport_tmr.mcgrp_wte,
                                 mcgrp_vport->query_interval_time);
    	}
   }
	return MLD_SUCCESS;
}

int mld_proto_query_max_response_time_set(uint32_t afi, uint32_t vid, uint32_t qmrt, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport)
		return MLD_SUCCESS;

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_QUERY_RESPONSE_INTERVAL)) {
		SET_FLAG(mcgrp_vport->flags,
			 MLD_IF_CFLAG_QUERY_RESPONSE_INTERVAL);
		L2MCD_LOG_INFO
		    ("%s(): MLD_IF_CFLAG_QUERY_RESPONSE_INTERVAL flag SET"
		     " for vlanid=%d", __FUNCTION__, vid);
	}

	/*Validate Query Interval to be > Query Response Interval */
	if (mcgrp_vport->query_interval_time <= qmrt) {
		L2MCD_LOG_INFO
		    ("%s(): query interval time is lesser than query response"
		     " time", __FUNCTION__);
      return  MLD_CLI_ERR_QRI_GT_QI;
    }

	/*Set max resp time */
	if (mcgrp_vport->max_response_time != qmrt)
		mcgrp_vport->max_response_time = (UINT16) qmrt;

	/*Calculate Group membership timer */
	mcgrp_vport->group_membership_time =
	    GROUP_MEMBERSHIP_INTERVAL(mcgrp_vport);

	/*Recalculate OQI if not configured */
	mcgrp_vport->older_host_present_time = OTHER_QUERIER_PRESENT_INTERVAL
	    (mcgrp_vport);
	return MLD_SUCCESS;
}

int mld_proto_fastleave_set(uint32_t afi, uint32_t vid, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport)
		return MLD_SUCCESS;

	if (!is_mld_fast_leave_configured(mcgrp_vport)) {
		SET_FLAG(mcgrp_vport->flags, MLD_FAST_LEAVE_CONFIGURED);
		L2MCD_LOG_INFO("%s(): MLD_FAST_LEAVE_CONFIGURED flag SET"
			       " for vlanid=%d", __FUNCTION__, vid);
	}

	return (MLD_SUCCESS);
}

int mld_proto_snoop_querier_set(uint32_t afi, uint16_t vid, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;
	VRF_INDEX vrf_index = MLD_DEFAULT_VRF_ID;
	MCGRP_CLASS *mcgrp = MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index);

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport)
		return MLD_SUCCESS;

	/*Set snooping querier flag */
	SET_FLAG(mcgrp_vport->flags, MLD_SNOOPING_QUERIER_ENABLED);
	L2MCD_LOG_INFO
	    ("%s(): MLD_SNOOPING_QUERIER_ENABLED flag SET for vlanid=%d afi = %d",
	     __FUNCTION__, vid, afi);
	mcgrp_start_stop_snooping_querier_api(mcgrp, mcgrp_vport, afi, TRUE);
	return MLD_SUCCESS;
}

void mcgrp_start_stop_snooping_querier_api(MCGRP_CLASS * mcgrp,
				      MCGRP_L3IF * mcgrp_vport, uint8_t afi, BOOLEAN flag)
{
	mld_vid_t gvid = 0;

	if (mcgrp == NULL || mcgrp_vport == NULL) {
		L2MCD_LOG_INFO("%s: returning mcgrp/mcgrp_vport is NULL",
			       __FUNCTION__);
		return;
	}
	gvid = mld_get_vlan_id(mcgrp_vport->vir_port_id);
	L2MCD_LOG_INFO("%s(%d): gvid: %d ", __FUNCTION__, __LINE__, gvid);
	if (is_mld_snooping_enabled(mcgrp_vport, afi)
	    && is_mld_snooping_querier_enabled(mcgrp_vport)
		&& !is_mld_l3_configured(mcgrp_vport)) {
		if (flag) {
			mcgrp_vport_start_querier_process(mcgrp, mcgrp_vport);
 			L2MCD_LOG_INFO
			    ("%s(): MLD_SNOOPING_QUERIER_ENABLED  SET for vlanid=%d",
			     __FUNCTION__, gvid);
		} else {
			mcgrp_vport_stop_querier_process(mcgrp, mcgrp_vport, TRUE);
       }
    }
}

void mld_replay_config(mld_vlan_node_t * vlan_node, int afi, MCGRP_CLASS * mld)
{
	uint32_t pport;
	MCGRP_L3IF *mcgrp_vport;
	mld_l2_static_group_t *static_grp;
	struct list *s_list;
	struct listnode *list_node;
	struct list *mrtr_list;
	mld_mrtr_t *mrt;
	MADDR_ST grp_addr;
	char str[46];
	UINT16 port;
	mld_cfg_t *cfg;
	mld_l3_if_type_t if_type;
	MCGRP_PORT_ENTRY *mcgrp_pport = NULL;

	cfg = vlan_node->mld_cfg[afi - 1];
	if (cfg) {
		if (cfg->param) {
			if (cfg->param->start_up_query_count !=
			    CU_DFLT_MLD_ROBUSTNESS)
				mld_proto_strtup_query_count_set(afi,
								 vlan_node->ivid,
								 cfg->
								 param->start_up_query_count,
                                 vlan_node->type);

			if (cfg->param->start_up_query_interval !=
			    ((cfg->param->cfg_query_interval_time) / 4))
				mld_proto_startup_query_interval_set(afi,
								     vlan_node->ivid,
								     cfg->
								     param->start_up_query_interval,
                                     vlan_node->type);

			if (cfg->param->LMQ_interval != CU_DFLT_LLQI_IN_MSEC) {
				mld_proto_lmqi_set(afi, vlan_node->ivid, 
						   cfg->param->LMQ_interval,
                                     vlan_node->type);
			}
	
			if (cfg->param->cfg_robustness_var !=
			    CU_DFLT_MLD_ROBUSTNESS)
				mld_proto_robustness_var_set(afi,
							     vlan_node->ivid,
							     cfg->
							     param->cfg_robustness_var,
                                     vlan_node->type);

			if (cfg->param->LMQ_count != CU_DFLT_MLD_ROBUSTNESS)
			 	mld_proto_lmqc_set(afi, vlan_node->ivid,
						   cfg->param->LMQ_count,
                           vlan_node->type);
		
			if (cfg->param->max_response_time !=
			    CU_DFLT_IGMP_RESPONSE_TIME)
				mld_proto_query_max_response_time_set(afi,
								      vlan_node->ivid,
								      cfg->
								      param->max_response_time,
                                      vlan_node->type);

			if (cfg->param->cfg_query_interval_time
											!= CU_DFLT_IGMP_QUERY_INTERVAL)
				mld_proto_query_interval_set(afi,
							     vlan_node->ivid,
							     vlan_node->gvid,
							     cfg->param->cfg_query_interval_time,
                                 vlan_node->type);

            if (afi == MLD_IP_IPV4_AFI) {
                if ((cfg->param->cfg_version != IGMP_VERSION_2) &&(cfg->param->cfg_version != IGMP_VERSION_NONE))
                    mld_if_set_version_api(MLD_DEFAULT_VRF_ID, vlan_node->gvid,
                            cfg->param->cfg_version, MLD_IP_IPV4_AFI, vlan_node->type);
            }
            else 
            {
                if (cfg->param->cfg_version != MLD_VERSION_1)
                    mld_if_set_version_api(MLD_DEFAULT_VRF_ID, vlan_node->gvid,
                            cfg->param->cfg_version, MLD_IP_IPV6_AFI, vlan_node->type);
            }

		}
	}
		port = mld_l3_get_port_from_ifindex(vlan_node->ifindex, vlan_node->type);
		mcgrp_vport = IS_IGMP_CLASS(mld) ? gIgmp.port_list[port] : 
												gMld.port_list[port];

    if (is_mld_snooping_enabled(mcgrp_vport, afi)) {
		mrtr_list = mld_vdb_vlan_get_mrtr_list(vlan_node, FALSE, afi);
		LIST_LOOP(mrtr_list, mrt, list_node) {
		//	pport = portdb_get_portindex_from_ifname
		//				     (mrt->ifname);
		    pport = mld_get_lif_ifindex_from_ifname(mrt->ifname,vlan_node->gvid,vlan_node->type); 
			L2MCD_LOG_INFO("%s %d %d %d", __FUNCTION__, vlan_node->ivid,
				       pport, mld_is_port_member_of_vlan(vlan_node,
									 pport));
			mcgrp_pport = mcgrp_find_phy_port_entry(mld, mcgrp_vport, pport);
		    if (mcgrp_pport == NULL || !mcgrp_pport->is_up) {
				L2MCD_LOG_INFO("%s Port %d is not up", __FUNCTION__, pport); 
            	continue;
        	}
			if (mld_is_port_member_of_vlan(vlan_node, pport)) {
				mcgrp_add_router_port(mld, mcgrp_vport, pport, TRUE,
						      MLD_PROTO_MROUTER,
						      DEFAULT_MROUTER_AGING_TIME, FALSE);
			}
		}
	}

   if_type = mld_get_l3if_type (vlan_node->ifindex);

   /* Get static group list accoriding to Vlan/Ve/Phy port */
   if (if_type == MLD_IFTYPE_L3PHY) 
	   s_list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, TRUE);
   else
	   s_list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, FALSE);

	LIST_LOOP(s_list, static_grp, list_node) {
			L2MCD_LOG_INFO("%s %d %s %s", __FUNCTION__, vlan_node->ivid, 
			       mld_ntop(&static_grp->grp_addr, str),
											static_grp->ifname);
	//	pport =
	//	   mld_get_port_ifindex(portdb_get_portindex_from_ifname
	//				     (static_grp->ifname));
        pport = mld_get_lif_ifindex_from_ifname(static_grp->ifname,vlan_node->gvid,vlan_node->type);
		if (mld_is_port_member_of_vlan(vlan_node, pport)) {
			mcast_set_ip_addr(&grp_addr, &static_grp->grp_addr);
			mcgrp_notify_l2_staticGroup_change(afi,
							   MLD_DEFAULT_VRF_ID,
							   &grp_addr,
							    port, 
							   pport, TRUE);
		}
	}

	if (mld_is_flag_set(vlan_node, afi, MLD_SNOOPING_QUERIER_ENABLED))
        mld_proto_snoop_querier_set(mld->afi, vlan_node->ivid,vlan_node->type);

	if (mld_is_flag_set(vlan_node, afi, MLD_FAST_LEAVE_CONFIGURED))
	    mld_proto_fastleave_set(afi,  vlan_node->ivid, vlan_node->type);

//	if (mld_is_flag_set(vlan_node, afi, MLD_SNOOPING_NO_FLOOD_ENABLED))
//	    mld_proto_intf_no_flood_set(afi,  vlan_node->ivid);

}

int mld_proto_strtup_query_count_set(uint32_t afi, uint16_t vid,
				 uint32_t startup_qc, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport) {
		return (MLD_SUCCESS);
	}

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_SNOOP_STARTUP_QUERY_COUNT)) {
		SET_FLAG(mcgrp_vport->flags,
			 MLD_IF_CFLAG_SNOOP_STARTUP_QUERY_COUNT);
		L2MCD_LOG_INFO
		    ("%s(): MLD_IF_CFLAG_SNOOP_STARTUP_QUERY_COUNT SET vlanid=%d",
		     __FUNCTION__, vid);
	}
	/*Set startup count */
	mcgrp_vport->start_up_query_count = (UINT16) startup_qc;
	
	return (MLD_SUCCESS);
}

int mld_proto_startup_query_interval_set(uint32_t afi, uint16_t vid,
				     uint32_t startup_qi, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;
    mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid,type);
	if (!mcgrp_vport) {
		return (MLD_SUCCESS);
	}

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFG_SNOOP_STARTUP_QUERY_INTERVAL)) {
		SET_FLAG(mcgrp_vport->flags,
			 MLD_IF_CFG_SNOOP_STARTUP_QUERY_INTERVAL);
		L2MCD_LOG_INFO
		    ("%s(): MLD_IF_CFG_SNOOP_STARTUP_QUERY_INTERVAL flag"
		     "SET for vlanid=%d", __FUNCTION__, vid);
	}

	/*set startup query interval */
	mcgrp_vport->start_up_query_interval = (UINT16) startup_qi;
	return (MLD_SUCCESS);
}

int mld_proto_robustness_var_set(uint32_t afi, uint32_t vid, uint32_t rv, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;

    mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport) {
		return MLD_SUCCESS;
	}

	if (!CHECK_FLAG(mcgrp_vport->flags, MLD_IF_CFLAG_ROBUSTNESS_VAR)) {
		SET_FLAG(mcgrp_vport->flags, MLD_IF_CFLAG_ROBUSTNESS_VAR);
		L2MCD_LOG_INFO("%s(): MLD_IF_CFLAG_ROBUSTNESS_VAR flag SET"
			       " for vlanid=%d", __FUNCTION__, vid);
    }

	mcgrp_vport->cfg_robustness_var = mcgrp_vport->robustness_var =
	    (UINT8) rv;
	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_SNOOP_STARTUP_QUERY_COUNT))
		mcgrp_vport->start_up_query_count = (UINT16) rv;

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_LAST_MEMBER_QUERY_COUNT))
		mcgrp_vport->LMQ_count = (UINT16) rv;

	/*Update the Interface GMI */
	mcgrp_vport->group_membership_time =
	    GROUP_MEMBERSHIP_INTERVAL(mcgrp_vport);

	/*Recalculate OQI if not configured */
	mcgrp_vport->older_host_present_time = 
								OTHER_QUERIER_PRESENT_INTERVAL(mcgrp_vport);
	return MLD_SUCCESS;
}

int mld_proto_lmqc_set(uint32_t afi, uint32_t vid, uint32_t lmqc, uint8_t type)
{
	MCGRP_L3IF *mcgrp_vport = NULL;

	mcgrp_vport = mld_get_l3if_from_vlanid(afi, vid, type);
	if (!mcgrp_vport)
		return MLD_SUCCESS;

	if (!CHECK_FLAG
	    (mcgrp_vport->flags, MLD_IF_CFLAG_LAST_MEMBER_QUERY_COUNT)) {
		SET_FLAG(mcgrp_vport->flags,
			 MLD_IF_CFLAG_LAST_MEMBER_QUERY_COUNT);
		L2MCD_LOG_INFO
		    ("%s(): MLD_IF_CFLAG_LAST_MEMBER_QUERY_COUNT flag SET"
		     " for vlanid=%d", __FUNCTION__, vid);
	}
	/*Set LMQC */
	mcgrp_vport->LMQ_count = (UINT8) lmqc;
	return (MLD_SUCCESS);
}

enum BOOLEAN mld_is_member2(PORT_MASK *mask, int port)
{
	  int tmp_port_num = mld_get_port_num(port);
	    if(!mld_only_code)
			      return TRUE;
		  else
			      return (IS_BIT_SET_BMP(mask, tmp_port_num));
}

void mld_clear_mask(PORT_MASK *mask)
{
	    if(!mld_only_code)
			        return;

		    MLD_PORT_MASK *tmp_mask = (MLD_PORT_MASK *) mask;
			BMP_CLRALL(tmp_mask, mld_get_port_bitmap_size());
}

enum BOOLEAN mld_is_member_tree(L2MCD_AVL_TREE *port_tree, uint32_t port)
{
	if(M_AVLL_FIND(*port_tree, &port))	
		return TRUE;
	return FALSE; 
}

void mcgrp_delete_all_router_ports(MCGRP_CLASS * mcgrp, MCGRP_L3IF * mcgrp_vport)
{
	 MCGRP_ROUTER_ENTRY  *mcgrp_rport = NULL, *mcgrp_next_rport = NULL;

	mcgrp_rport = mcgrp_vport->rtr_port_list;
	while (mcgrp_rport) {
		mcgrp_next_rport = mcgrp_rport->next;
		mcgrp_delete_router_port(mcgrp, mcgrp_vport,
					 mcgrp_rport->phy_port_id);
		mcgrp_rport = mcgrp_next_rport;
	}
}

//v4/v6 compliant
void mcgrp_activate_l2_static_groups(MCGRP_CLASS * mcgrp,
				//UINT16 vir_port_id, UINT16 target_port)
				UINT16 vir_port_id, UINT32 target_port)
{
	if (!mcgrp) {
		L2MCD_LOG_INFO("mcgrp is null %s", __FUNCTION__);
		return;
	}
	MCGRP_L3IF *mcgrp_vport;
	MCGRP_STATIC_ENTRY *mcgrp_entry;

	mcgrp_vport = IS_IGMP_CLASS(mcgrp) ? gIgmp.port_list[vir_port_id] :
	    gMld.port_list[vir_port_id];

	if (mcgrp_vport == NULL) {
		return;
	}

	mcgrp_entry = mcgrp_vport->static_mcgrp_list_head;
	for (; mcgrp_entry; mcgrp_entry = mcgrp_entry->next) {
		if (mld_is_member_tree(&(mcgrp_entry->port_tree), target_port)) {
			mcgrp_update_l2_static_group(mcgrp, mcgrp_vport,
						     mcgrp_entry, IS_EXCL,
						     target_port);
		}
	}
}

BOOLEAN mld_l2_staticGroup_exists_on_port(mcast_grp_addr_t * group_addr,
				  PORT_ID port_id, UINT32 phy_port)
{
    VRF_INDEX            vrf_index = IP6_PORT_VRF_INDEX(port_id);
	MCGRP_CLASS *mld =
	    MCGRP_GET_INSTANCE_FROM_VRFINDEX(group_addr->afi, vrf_index);
	MCGRP_STATIC_ENTRY *mld_entry = NULL;
	MCGRP_L3IF *mcgrp_vport = NULL;
	MADDR_ST g_addr;
	
	if (!mld)
		return FALSE;

    mcgrp_vport = IS_IGMP_CLASS(mld) ? gIgmp.port_list[port_id] :
											gMld.port_list[port_id];

    mld_entry = mcgrp_vport->static_mcgrp_list_head;
	mcast_set_ip_addr(&g_addr, group_addr);
	while (mld_entry) {
    	if (mld_entry->port_num == port_id
		    && mcast_same_addr(&g_addr, &mld_entry->group_address)) {
			if (mld_is_member_tree( &(mld_entry->port_tree), phy_port))
            {
                return TRUE;
            }
        }

        mld_entry = mld_entry->next;
    }

    return FALSE;
}

BOOLEAN mcast_validate_igmp_packet(IGMP_MESSAGE * sptr_igmp_message,
			   UINT16 igmp_pkt_size, BOOLEAN dbg_enabled)
{
	UINT16 g, num_grps = 0;
	UINT32 group_address = 0;
	IGMPV3_GROUP_RECORD *grp_rec = NULL;
	IGMPV3_REPORT *igmpv3_rep = (IGMPV3_REPORT *) sptr_igmp_message;
	UINT16 pkt_size = 0;
	UINT8 igmpver;
	UINT8 rx_max_resp_time = sptr_igmp_message->maximum_response_time;
	IGMPV3_MESSAGE *igmpv3_msg = (IGMPV3_MESSAGE *) sptr_igmp_message;
	UINT16 num_srcs = 0;
	UINT16 pkt_sz = 0;

	switch (sptr_igmp_message->type) {
	case IGMP_MEMBERSHIP_QUERY_TYPE:
		// Determine the query's version
		IGMP_EVAL_QUERY_VERSION(igmpver, rx_max_resp_time,
					igmp_pkt_size);
		switch (igmpver) {
		case IGMP_VERSION_1:
		case IGMP_VERSION_2:
			if (igmp_pkt_size > sizeof (IGMP_MESSAGE))
				return FALSE;

			break;

		case IGMP_VERSION_3:
			num_srcs = net_to_host_short(igmpv3_msg->num_srcs);
  			pkt_sz =
 				sizeof (IGMPV3_MESSAGE) +
                ((num_srcs>1)?((num_srcs-1)*sizeof(UINT32)):0 );

			/*Include size of num_srcs(if num_srcs = 0,include length for ip address 0) + 1  byte for RV, QI,
			 * UINT8   reserved                : 4;
			 * UINT8 suppress_router_process  : 1;
			 * UINT8 robustness_var     : 3; // querier's robustness variable
			 * UINT8 query_interval_code;  //querier's interval code
			 * UINT16 num_srcs;
			 **/
			if (pkt_sz != igmp_pkt_size) {
				return FALSE;
			}
			break;

		default:
			return FALSE;
			break;
		}

		break;
	case IGMP_V2_MEMBERSHIP_REPORT_TYPE:
	case IGMP_V2_LEAVE_GROUP_TYPE:
		group_address =
		    (UINT32) net_to_host_long(sptr_igmp_message->group_address);

		if (igmp_check_valid_range(group_address) == FALSE) {

			L2MCD_LOG_INFO("%s: Dropped because group address not valid %x.", FN, group_address);
			return FALSE;
		}

		break;

	case IGMP_V3_MEMBERSHIP_REPORT_TYPE:

		num_grps = net_to_host_short(igmpv3_rep->num_grps);
		grp_rec = igmpv3_rep->group_record;
		pkt_size = sizeof (IGMP_MESSAGE);

		for (g = 0; g < num_grps; g++) {
			group_address =
			    (UINT32) net_to_host_long(grp_rec->group_address);

			if (igmp_check_valid_range(group_address)) {
				num_srcs = net_to_host_short(grp_rec->num_srcs);
				pkt_size =
				    pkt_size + IGMPV3_GROUP_REC_HDR_SIZE +
				    ((num_srcs) * sizeof (UINT32));
			} else {
				return FALSE;
			}

			grp_rec = NEXT_GRP_REC(grp_rec);
		}

		if (pkt_size != igmp_pkt_size) {
			return FALSE;
		}
	}
	return TRUE;
}


void mld_process_pimv2_query(MCGRP_CLASS * mld, MADDR_ST * src,
			PIM_V2_HDR * pim_v2_hdr,
			MCGRP_L3IF * mcgrp_vport, MCGRP_PORT_ENTRY * mcgrp_port)
{
    PIM_HELLO_MSG   *pim_hello;
	MCGRP_ROUTER_ENTRY *mcgrp_rport = NULL;
	uint16_t hold_time;

    if (IS_IGMP_CLASS(mld))
    {
        mld->igmp_stats[mcgrp_vport->vir_port_id].pim_hello_pkt_rcvd++;
    }
    else
    {
	    mld->mld_stats[mcgrp_vport->vir_port_id].pim_hello_pkt_rcvd++;
    }

    /* add the mrouter port only if snooping is enabled */
    if(!is_mld_snooping_enabled(mcgrp_vport, mld->afi))   
    {
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] snooping not enabled for vlan afi:%d",__FUNCTION__, __LINE__, mcgrp_vport->vir_port_id,mld->afi);
        return;
    }
	mcgrp_rport = mcgrp_find_router_port_entry(mcgrp_vport, mcgrp_port->phy_port_id);
	if (mcgrp_rport && mcgrp_rport->type == MLD_PROTO_MROUTER) 
    {
        L2MCD_VLAN_LOG_INFO(mcgrp_vport->vir_port_id, "%s:%d:[vlan:%d] afi:%d rport_type is:%d",__FUNCTION__, __LINE__,mcgrp_vport->vir_port_id,mld->afi,mcgrp_rport->type);
    	return;
    }
    //add to router port list for the vlan
	pim_hello =  (PIM_HELLO_MSG *) ((UINT8 *) pim_v2_hdr + sizeof (PIM_V2_HDR));

	if ((pim_hello->option_type == 1) && (pim_hello->option_length == 2)) {
		hold_time =   net_to_host_short((UINT16)pim_hello->holdtime);
	} else {
		hold_time = DEFAULT_MROUTER_AGING_TIME;
	}

	mcgrp_add_router_port(mld, mcgrp_vport, mcgrp_port->phy_port_id, FALSE,	MLD_PIM_MROUTER, hold_time, FALSE);
    return;
}

void igmp_process_pimv2_packet(char *sptr_ip6_hdr,  UINT16 vir_port_id, UINT32 phy_port_id)
{
	MADDR_ST src_addr;
	MADDR_ST dst_addr;

	VRF_INDEX vrf_index = IP6_PORT_VRF_INDEX(vir_port_id);
	MCGRP_CLASS *mld = IGMP_GET_INSTANCE_FROM_VRFINDEX(vrf_index);
	MCGRP_L3IF *mcgrp_vport;
	MCGRP_PORT_ENTRY *mcgrp_port;
	IP_HEADER *sptr_iphdr = (IP_HEADER *) sptr_ip6_hdr;
	UINT16 iphdr_length;
	UINT16 pim_length;
	PIM_V2_HDR *pim_v2_hdr;

	mcast_init_addr(&src_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
	mcast_init_addr(&dst_addr, IP_IPV4_AFI, MADDR_GET_FULL_PLEN(IP_IPV4_AFI));
	mcast_set_ipv4_addr(&src_addr, ntohl(sptr_iphdr->source_ip_address));
	mcast_set_ipv4_addr(&dst_addr, ntohl(sptr_iphdr->destination_ip_address));
	iphdr_length = 	(UINT16) (sptr_iphdr->version_header_length.header_length << 2);
	pim_v2_hdr = (PIM_V2_HDR *) ((UINT8 *) sptr_iphdr + iphdr_length);
	pim_length = net_to_host_short(sptr_iphdr->total_length) - iphdr_length;
	//pim_length = (sptr_iphdr->total_length) - iphdr_length;
	if (calculate_ip_checksum(NULL, (UINT8 *) pim_v2_hdr, pim_length) != 0x0000) 
    {
		L2MCD_LOG_NOTICE("%s(%d) checksum failed on recieved PIM packet iphdr_length:%d pim_length:%d ",  
           __FUNCTION__, __LINE__, iphdr_length, pim_length);
		return;
	}

	if (pim_v2_hdr->pim_version != PIM_V2) 
    {
		L2MCD_LOG_NOTICE("%s version does not match %d for recievd packet", __FUNCTION__, pim_v2_hdr->pim_version);
		return;
	}
	mcgrp_vport = gIgmp.port_list[vir_port_id];
	mcgrp_port = mcgrp_find_phy_port_entry(mld, mcgrp_vport, phy_port_id);

	if (mcgrp_vport == NULL || mcgrp_port == NULL) {
		L2MCD_LOG_NOTICE("%s vport %p  pphort %p port_id %d %d", __FUNCTION__, mcgrp_vport, mcgrp_port,	vir_port_id, phy_port_id);
		return;
	}

	L2MCD_PKT_PRINT(vir_port_id,"PIM_RX vid:%d type %d on Port %s,%s Grp %s Src %s",
			 vir_port_id, pim_v2_hdr->type,
			 mld_get_if_name_from_ifindex(phy_port_id),
			 mld_get_if_name_from_port(vir_port_id),
			 mcast_print_addr(&dst_addr), mcast_print_addr(&src_addr));

	switch (pim_v2_hdr->type) {
		case PIM_QUERY:
			mld_process_pimv2_query(mld, &src_addr,	(PIM_V2_HDR *) pim_v2_hdr, mcgrp_vport,	mcgrp_port);
			break;
		default:
			break;
	}
	return;
}
