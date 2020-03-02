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
#include "mld_vlan_db.h"
#include "l2mcd_mld_port.h"
#include "l2mcd_portdb.h"
#include "l2mcd.h"
#include "l2mcd_dbsync.h"

/*Gvid to ivid mapping*/
static hashGrowGeneric *mld_portdb_gvid_to_ivid_hash = NULL;
extern L2MCD_AVL_TREE *mld_portdb_tree;
#define MLD_PORTDB_GVID_HASH_INIT_SIZE 100
unsigned int mld_portdb_get_ivid_from_gvid(uint32_t vlan_id, uint8_t type);
mld_vlan_db_t mld_vlan_db;
struct list *snooping_enabled_vlans[MCAST_AFI_MAX];
struct list *
mld_vdb_vlan_get_mrtr_list(mld_vlan_node_t *vlan_node, int create, uint8_t afi);
extern BOOLEAN pim_enabled (UINT32 afi, UINT16 port);
extern int mld_set_vlan_dcm_flag(uint32_t gvid,uint8_t type);
uint32_t
mld_is_flag_set(mld_vlan_node_t *vlan_p, uint8_t afi, uint32_t flag)
{
	return (vlan_p->flags[afi -1] & flag);

}

void
mld_set_vlan_flag(mld_vlan_node_t *vlan_p, uint8_t afi, uint32_t flag)
{
	vlan_p->flags[afi -1] |= flag; 
}

void
mld_unset_vlan_flag(mld_vlan_node_t *vlan_p, uint8_t afi, uint32_t flag)
{
    vlan_p->flags[afi -1] &= ~flag;
}

void
mld_vlan_add_list(mld_vlan_node_t *vlan_p, uint8_t afi)
{
	if(listnode_lookup(snooping_enabled_vlans[afi - 1], vlan_p)!= NULL)
    {
		return ;
    }
	
	listnode_add(snooping_enabled_vlans[afi - 1], vlan_p);
}


void
mld_vlan_del_list(mld_vlan_node_t *vlan_p, uint8_t afi)
{
    if(listnode_lookup(snooping_enabled_vlans[afi - 1], vlan_p) == NULL)
    {
        return ;
    }
    listnode_delete(snooping_enabled_vlans[afi - 1], vlan_p);
}

int mld_vdb_init( )
{
    int rc = MLD_VLAN_DB_SUCCESS;
	uint8_t afi;
    /* Create the VLAN tree */
	static int gvid_offset= M_AVLL_OFFSETOF(mld_vlan_node_t, gvid);
    mld_vlan_db.vdb_tree=L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &gvid_offset, NULL);

	for(afi = 0 ; afi < MCAST_AFI_MAX; afi++)
    {
        snooping_enabled_vlans[afi] = list_new();
    }
	L2MCD_INIT_LOG("%s VDB Init. Done #afis:%d", __FUNCTION__, afi);
    return rc;
}


/* See mld_vlan_db.h for description */
mld_vlan_node_t *mld_vdb_vlan_get(uint32_t vlan_id,uint8_t type )
{
	mld_vlan_node_t *vlan_node = NULL;
    vlan_node = M_AVLL_FIND(mld_vlan_db.vdb_tree, &vlan_id);
	return (vlan_node);
}

int mld_vdb_vlan_is_present_in_protocol(mld_vlan_node_t *vlan_node, uint8_t afi)
{
	return (mld_is_flag_set(vlan_node,  afi, MLD_SNP_ADDED_PROTOCOL));
}


int mld_add_static_grp_node_to_pending_list(mld_vlan_node_t *vlan_node, 
		                                    mld_l2_static_group_t *input_msg,
		                                    int add, BOOLEAN is_ve)
{

    struct list *list_head = mld_vdb_vlan_get_static_grp_list(vlan_node, TRUE, input_msg->grp_addr.afi, is_ve);
	mld_l2_static_group_t *msg = NULL;
	char str[46];

    if(!list_head)
       return MLD_ERROR;

	msg = (mld_l2_static_group_t *) listnode_lookup(list_head, input_msg);

	if(!msg) {	
		if(add) {
    		msg = MLD_CALLOC(1, sizeof(mld_l2_static_group_t));
			if(NULL == msg) {
				L2MCD_LOG_INFO("%s %d static group malloc failed %s %d %s", __FUNCTION__, __LINE__, 
								mld_ntop(&input_msg->grp_addr, str), vlan_node->ivid, msg->ifname);
				return (MLD_ERROR);
			}
			
			/* fill the data */
			memcpy(&msg->grp_addr, &input_msg->grp_addr, sizeof(mcast_grp_addr_t));
			strncpy(msg->ifname, input_msg->ifname, INTERFACE_NAMSIZ);
            L2MCD_LOG_INFO("%s %d static group %s %d %s %s %d", __FUNCTION__, __LINE__,
                                mld_ntop(&input_msg->grp_addr, str), vlan_node->ivid, msg->ifname,
								input_msg->ifname, INTERFACE_NAMSIZ);
			listnode_add(list_head, msg);
		} else
			return (MLD_ERROR); 
	}
	if(!add) {
		L2MCD_LOG_INFO("%s deleting the group %s %d %s %p", __FUNCTION__,
						mld_ntop(&input_msg->grp_addr, str), vlan_node->ivid, 
						input_msg->ifname, msg);
		listnode_delete(list_head, msg);
	}

    return MLD_SUCCESS;
}

int mld_add_static_mrtr_to_pending_list(mld_vlan_node_t *vlan_node, char *if_name, int add, uint8_t afi)
{

    struct list *list_head = mld_vdb_vlan_get_mrtr_list(vlan_node, add, afi);
    mld_mrtr_t *msg = NULL;

    if(!list_head)
       return MLD_ERROR;

    msg = (mld_mrtr_t *)listnode_lookup(list_head, (void *)if_name);
    if(!msg) {
        if(add) {
            msg = MLD_CALLOC(1, sizeof(mld_mrtr_t));
            if(NULL == msg) {
                L2MCD_LOG_INFO("%s %d static group malloc failed %d %s", __FUNCTION__, __LINE__,
                                vlan_node->ivid, if_name);
                return (MLD_ERROR);
            }

            /* fill the data */
			strncpy(msg->ifname, if_name, INTERFACE_NAMSIZ);
            listnode_add(list_head, msg);
        } else
            return (MLD_ERROR);
    }
	
	if(!add) {
		listnode_delete(list_head, msg);
	}

    return MLD_SUCCESS;
}

void mld_free_cfg_param(mld_vlan_node_t *vlan_node, uint8_t afi)
{
	mld_cfg_t *cfg;

    cfg = mld_vdb_vlan_get_cfg(vlan_node, FALSE, afi);

    if(!cfg) {
        L2MCD_LOG_INFO("%s %d cfg is not available for vlan %d", __FUNCTION__, __LINE__, vlan_node->ivid);
        return ;
    }

	if(cfg->param)
		MLD_FREE(cfg->param);
}

void mld_free_cfg(mld_vlan_node_t *vlan_node, uint8_t afi)
{
    mld_cfg_t *cfg;

    cfg = mld_vdb_vlan_get_cfg(vlan_node, FALSE, afi);

    if(!cfg) {
        L2MCD_LOG_INFO("%s %d cfg is not available for vlan %d", __FUNCTION__, __LINE__, vlan_node->ivid);
        return ;
    }

    if(cfg)
        MLD_FREE(cfg);
}

int mld_vlan_port_cmp_cb (void *keya,void *keyb)
{
	return (*(UINT32 *)keya - *(UINT32 *) keyb);
}

/* See mld_vlan_db.h for description */
mld_vlan_node_t *
mld_vdb_vlan_create(mld_vlan_db_t *vlan_db, uint32_t vlan_id, uint8_t type,
							uint32_t flags, uint32_t vlan_flags, uint16_t ivid, 
							char *name, int vlan_creation_type)
{
    mld_vlan_node_t *vlan_node = NULL;
    int bmap_size = 0;
    uint8_t afi;

    if (!vlan_db)
    {
        goto vdb_vid_create_done;
    }


    vlan_node = M_AVLL_FIND(vlan_db->vdb_tree, &vlan_id);

    if (vlan_node) 
    {
     	L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] vlan node already present vlan_node->ivid: %d ivid: %d ", 
				__FUNCTION__, __LINE__, vlan_id, vlan_node->ivid, ivid);
        /* Since the VLAN already exists, only update the relevant
         * variables */
		vlan_node->vlan_flags |= vlan_flags;
		vlan_node->ivid = ivid;
		/* Update pim_nbrshp_count value to zero as ivid is getting updated*/
		vlan_node->multi_access_ntwrk_flag = 0;
        if(vlan_node->ivid)
        {
            if(type == MLD_BD) 
            {
                vlan_node->ifindex = vlan_id;	// Phy/Router ifindex
                vlan_node->ve_ifindex = 0;
            }
            else
            {
                if (vlan_id < MLD_MAX_VLANS) 
                {
                    vlan_node->ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_node->ivid);
                    vlan_node->ve_ifindex = 0;
                }
                else if (vlan_id >= MLD_MAX_VLANS) 
                {
                    vlan_node->ifindex = vlan_id;	// Phy/Router ifindex
                    vlan_node->ve_ifindex = vlan_id;	// Phy/Router ifindex
                }
            }
        } 
        else 
        {
            /* For Router port ivid will be 0 */
            vlan_node->ifindex = vlan_id;
			vlan_node->ve_ifindex = vlan_id;	// Phy/Router ifindex
		}
		
		SET_FLAG(vlan_node->rcvd_nsm_add, vlan_creation_type);
		if(vlan_node->rcvd_nsm_add &  MLD_VLAN_NSM) 
		{
			mld_portdb_add_gvid(vlan_node->ivid, vlan_node->gvid);
		}

        goto vdb_vid_create_done;
    }

    L2MCD_LOG_INFO("%s(%d) bmap_size: %d ", __FUNCTION__, __LINE__, bmap_size);
	
	/* Create a new node and populate the variables */
    vlan_node = (mld_vlan_node_t *) calloc(1, (sizeof(mld_vlan_node_t)));
    if (!vlan_node) 
    {
        //rc = MLD_VLAN_DB_ENOMEM;
        goto vdb_vid_create_done;
    }
    
    /* creating forward referencing structure as well, since the version is being refrered before configuring it. */

    for(afi = 1; afi <= MCAST_AFI_MAX; afi++)
        mld_vdb_vlan_get_cfg_param(vlan_node, 1, afi);
    M_AVLL_INIT_NODE(vlan_node->node);
    vlan_node->gvid = vlan_id;
	vlan_node->type = type;
	vlan_node->vlan_flags = vlan_flags;
	vlan_node->ivid = ivid;
	vlan_node->bmap_size = bmap_size / sizeof(uint32_t); //(((max_port_size + 31 )/32) * sizeof(uint32_t));
    if (vlan_node->ivid)
    {
        if(type == MLD_BD)
        {
            vlan_node->ifindex = vlan_id;	// Phy/Router ifindex
            vlan_node->ve_ifindex = 0;
        } 
        else 
        {
            if (vlan_id < MLD_MAX_VLANS) 
            {
                vlan_node->ifindex = l2mcd_ifindex_create_logical_idx(L2MCD_IF_TYPE_SVI, vlan_node->ivid);
                vlan_node->ve_ifindex = 0;
            }
            else if (vlan_id >= MLD_MAX_VLANS)
            {
                vlan_node->ifindex = vlan_id;
                vlan_node->ve_ifindex = vlan_id;	
            }
        }
    }
    else 
    {
		/* For Router port ivid will be 0 */
		vlan_node->ifindex = vlan_id;
		vlan_node->ve_ifindex = vlan_id;	// Phy/Router ifindex
	}

	strncpy(vlan_node->name, name, INTERFACE_NAMSIZ);
	static int vdb_port_offset;
    vdb_port_offset=M_AVLL_OFFSETOF(mld_vlan_port_t, ifindex);
    vlan_node->port_tree= L2MCD_AVL_CREATE(l2mcd_avl_compare_u32, (void *) &vdb_port_offset, NULL);

	SET_FLAG(vlan_node->rcvd_nsm_add, vlan_creation_type);

    M_AVLL_INSERT(vlan_db->vdb_tree, vlan_node);
	L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] Created vlan_node %p gvid:0x%x ivid:0x%x ifidx:0x%x bmap_size:0x%x igmpver:%d", 
		 __FUNCTION__, __LINE__, vlan_id, vlan_node, vlan_node->gvid, vlan_node->ivid, vlan_node->ifindex, bmap_size, vlan_node->cfg_version);

	if(vlan_node->rcvd_nsm_add & MLD_VLAN_NSM)
		mld_portdb_add_gvid( vlan_node->ivid, vlan_node->gvid);

vdb_vid_create_done:
    return vlan_node;
}

/* See mld_vlan_db.h for description */
int mld_vdb_vlan_del(mld_vlan_db_t *vlan_db, uint32_t vlan_id,uint8_t type)
{
    mld_vlan_node_t *vlan_node = NULL;
    int rc = MLD_VLAN_DB_SUCCESS;
    uint8_t key[MLD_VLAN_KEY_SIZE];

    key[MLD_VLAN_KEY_TYPE_OFFSET] = type;
    memcpy(&key[MLD_VLAN_KEY_ID_OFFSET],&vlan_id,sizeof(uint32_t));

    if(!vlan_db) {
        rc = MLD_VLAN_DB_ENULL_PARAM;
        goto vdb_vid_del_done;
    }

    vlan_node = mld_vdb_vlan_get(vlan_id, type);
    if(!vlan_node)
        goto vdb_vid_del_done;

    /* Remove the vlan node from the tree first */
    M_AVLL_DELETE(mld_vlan_db.vdb_tree,vlan_node);
    M_AVLL_DESTROY(vlan_node->port_tree, NULL);	
	mld_portdb_delete_gvid(vlan_id);
    /* Cleanup the memory used by the VLAN node */
    if(vlan_node)
        mld_vlan_cleanup(vlan_node);

vdb_vid_del_done:
    return rc;
}

/* See mld_vlan_db.h for description */
int mld_vdb_add_port_to_vlan(mld_vlan_db_t *vlan_db, uint32_t vlan_id,uint32_t port_num,uint8_t type)
{
    mld_vlan_node_t *vlan_node = NULL;
    int rc = MLD_VLAN_DB_SUCCESS;

	mld_vlan_port_t *vlan_port;
    uint8_t key[MLD_VLAN_KEY_SIZE];
    key[MLD_VLAN_KEY_TYPE_OFFSET] = type;
    memcpy(&key[MLD_VLAN_KEY_ID_OFFSET],&vlan_id,sizeof(uint32_t));

    vlan_node = mld_vdb_vlan_get(vlan_id, type);
    if(!vlan_node)
		{
			L2MCD_LOG_INFO(" %s vlan does not exist %d", __FUNCTION__, vlan_id);
			goto vdb_apv_done;
    }


   	vlan_port = calloc(1,sizeof(mld_vlan_port_t));
   	if(vlan_port == NULL)
       	return (MLD_VLAN_DB_ENOMEM);
	M_AVLL_INIT_NODE(vlan_port->node); 
   	vlan_port->ifindex = port_num;
   	if (!M_AVLL_INSERT(vlan_node->port_tree,vlan_port)){
       	free(vlan_port);
       	return(MLD_VLAN_DB_ENOMEM) ;
   	}
    L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] ivid:%d port:%d  port-tree-add %s", 
			 __FUNCTION__, __LINE__, vlan_id, vlan_node->ivid, port_num, vlan_port?"Done":" ???");
vdb_apv_done:
    return rc;
}

/* See mld_vlan_db.h for description */
int
mld_vdb_del_port_frm_vlan(mld_vlan_db_t *vlan_db, uint32_t vlan_id,uint32_t  port_num, uint8_t type)
{
    mld_vlan_node_t *vlan_node = NULL;
    int rc = MLD_VLAN_DB_SUCCESS;
    uint8_t key[MLD_VLAN_KEY_SIZE];
    mld_vlan_port_t *vlan_port;

    key[MLD_VLAN_KEY_TYPE_OFFSET] = type;
    memcpy(&key[MLD_VLAN_KEY_ID_OFFSET],&vlan_id,sizeof(uint32_t));

    if(!vlan_db) {
        rc = MLD_VLAN_DB_ENULL_PARAM;
        goto vdb_dpv_done;
    }

    /* Check whether the VLAN exists  */
	vlan_node = mld_vdb_vlan_get(vlan_id, type);
    if(!vlan_node) {
        rc = MLD_VLAN_DB_ENOVLAN;
        goto vdb_dpv_done;
    }
	vlan_port = M_AVLL_FIND(vlan_node->port_tree, &port_num);
    L2MCD_VLAN_LOG_INFO(vlan_id, "%s:%d:[vlan:%d] ivid:%d port:%d  port-tree-rem %s", 
			 __FUNCTION__, __LINE__, vlan_id, vlan_node->ivid, port_num, vlan_port?"Done":" ???");
	if (vlan_port) 
	{
		M_AVLL_DELETE(vlan_node->port_tree,vlan_port);
		free(vlan_port);
	}
vdb_dpv_done:
    return rc;
}


int
mld_lookup_gvid_by_ivid(mld_vlan_node_t *vlan_node, uint16_t vlan_id, unsigned long *gvid)
{

    int ret;
    unsigned long ivid_ptr;

    ret = hashGrowGenericGet(mld_portdb_gvid_to_ivid_hash, vlan_id, (unsigned long *)&ivid_ptr);

    if(ret) {
		*gvid = ivid_ptr;
        return  0;
    }
    return MLD_IVID_GVID_MAP_NOT_FOUND; //invalid ivid;
}

/* See mld_vlan_db.h for description */
void mld_vlan_cleanup(mld_vlan_node_t *vlan)
{
    if(!vlan)
        return;

    /* Free the vlan node itself */
    MLD_FREE(vlan);

    return;
}

L2MCD_AVL_TREE  mld_vlan_get_vdbtree(void)
{
	return(mld_vlan_db.vdb_tree);
}
mld_vlan_db_t * mld_vlan_get_db()
{
	return (&mld_vlan_db);
}

uint8_t mld_is_port_member_of_vlan(mld_vlan_node_t *vlan, uint32_t port_num)
{
	if (M_AVLL_FIND(vlan->port_tree, &port_num))	
		return TRUE;
	return FALSE; 

}

uint8_t is_mld_snooping_enabled(MCGRP_L3IF *mcgrp_vport, uint8_t afi)
{
	if((mcgrp_vport->flags & MLD_SNOOPING_ENABLED))
		return TRUE;

	return FALSE;
}

uint8_t is_mld_vlan_snooping_enabled(mld_vlan_node_t *vlan, uint8_t afi)
{
	if (!CHECK_FLAG(vlan->rcvd_nsm_add,  MLD_VLAN_NSM))
		return FALSE;

    if (mld_is_flag_set(vlan, afi, MLD_SNOOPING_ENABLED))
        return TRUE;
    
    return FALSE;
}

uint8_t is_mld_fast_leave_configured(MCGRP_L3IF *mcgrp_vport)
{
	if (mcgrp_vport->flags & MLD_FAST_LEAVE_CONFIGURED)
		return TRUE;

	return FALSE;
}
uint8_t is_mld_snooping_querier_enabled(MCGRP_L3IF *mcgrp_vport)
{
	if (MLD_SNOOPING_QUERIER_ENABLED & mcgrp_vport->flags)
		return TRUE;
	return FALSE;
}


uint8_t is_mld_l3_configured(MCGRP_L3IF *mcgrp_vport)
{
	if(MLD_VE_PIM_ENABLED & mcgrp_vport->flags)
		return TRUE;	

	return FALSE;
}		
	
uint8_t is_mld_vlan_l3_enabled(mld_vlan_node_t *vlan, uint8_t afi)
{
	if(mld_is_flag_set(vlan,  afi, MLD_VE_ENABLED))
        return TRUE;
    
	return FALSE;
}

int is_mld_vlan_snooping_allowed(uint32_t vid, uint16_t vrfid, MCGRP_CLASS  *mld,
													int glb_mode,uint8_t type)
{
    MCGRP_GLOBAL_CLASS  *mcgrp_glb = (IS_IGMP_CLASS(mld) ? &gIgmp : &gMld);
    mld_vlan_node_t *vlan = mld_vdb_vlan_get(vid,type);
	if (IS_IGMP_CLASS(mld)) 
    {
        if(mcgrp_glb->mld_snp_vlan_count == IGMP_MAX_VLAN_SUPPORT_REACHED) {
           L2MCD_LOG_INFO("%s(%d) IGMP Max Vlan Support Reached", __FUNCTION__, __LINE__);
           return MLD_MAX_VLAN_REACHED;
        }
    } else {	
        if(mcgrp_glb->mld_snp_vlan_count == MLD_MAX_VLAN_SUPPORT_REACHED)
        {
            L2MCD_LOG_INFO("%s(%d) mld max vlan support is reached", __FUNCTION__, __LINE__);
            return MLD_MAX_VLAN_REACHED;		
        }
    }

    if (vlan && mld_is_flag_set(vlan,  mld->afi, MLD_VLAN_DELETED))
    {
        L2MCD_LOG_INFO("%s(%d) %s vlan is already in deletion process vlan %d", __FUNCTION__, __LINE__, IS_IGMP_CLASS(mld)?"IGMP":"MLD", vlan->gvid);
        return MLD_FAIL;
    }

	if(vlan && mld_is_flag_set(vlan,  mld->afi, MLD_SNOOPING_DISABLED))
	{
		L2MCD_LOG_INFO("%s(%d) %s snooping is disabled on this vlan %d", __FUNCTION__, __LINE__, IS_IGMP_CLASS(mld)?"IGMP":"MLD", vlan->gvid);
		return MLD_VLAN_SNOOP_DISABLED;
	}
  
    if(vlan && !(vlan->rcvd_nsm_add & MLD_VLAN_NSM))
	{
		L2MCD_LOG_INFO("%s(%d), did not receive vlan from nsm", __FUNCTION__, __LINE__);
        return MLD_VLAN_FWD_REF;
	}
	if(vlan && mld_is_flag_set(vlan, mld->afi, MLD_SNOOPING_ENABLED)) 
	{
        L2MCD_LOG_INFO("%s(%d) %s snooping is enabled on this vlan %d", __FUNCTION__, __LINE__, IS_IGMP_CLASS(mld)?"IGMP":"MLD", vlan->gvid);
        return MLD_SUCCESS;
    }
	return MLD_FAIL;

}

mld_cfg_t *mld_vdb_vlan_get_cfg(mld_vlan_node_t *vlan_node, int create, uint8_t afi)
{
	if(!vlan_node->mld_cfg[afi - 1]) 
	{
		if(create) 
			vlan_node->mld_cfg[afi - 1] = calloc(1, sizeof(mld_cfg_t));
		else
			return (NULL);
	}
	return (vlan_node->mld_cfg[afi -1]);
}

mld_cfg_param_t *mld_vdb_vlan_get_cfg_param(mld_vlan_node_t *vlan_node, int create, uint8_t afi)
{
	mld_cfg_t *cfg;

	cfg = mld_vdb_vlan_get_cfg(vlan_node, create, afi);
	if (!cfg) {
		if (create)
			L2MCD_LOG_INFO("%s %d cfg could not malloc %d %d", 
					__FUNCTION__, __LINE__, vlan_node->ivid, create);
		return (NULL);
	}

	if (!cfg->param) {
		if (create) {		
			cfg->param = calloc(1, sizeof(mld_cfg_param_t));
			mld_intialize_with_def_values(cfg->param);
		} else
			return (NULL);
	}
	return (cfg->param);
}

struct list *mld_vdb_vlan_get_mrtr_list(mld_vlan_node_t *vlan_node, int create, uint8_t afi)
{
	mld_cfg_t *cfg;

    cfg = mld_vdb_vlan_get_cfg(vlan_node, create, afi);
    if (!cfg) 
	{
		if(create)
        	L2MCD_LOG_INFO("%s %d cfg could not malloc %d %d",
					__FUNCTION__, __LINE__, vlan_node->ivid, create);
        return (NULL);
    }
	
    if (!cfg->mrtr_list)
	{
        if(create)
        {
            cfg->mrtr_list = list_new();
        }
        else
        {
            return (NULL);
        }
	}
    return (cfg->mrtr_list);
}

struct list *
mld_vdb_vlan_get_static_grp_list(mld_vlan_node_t *vlan_node, int create, uint8_t afi, BOOLEAN is_ve)
{
	mld_cfg_t *cfg = NULL;

    cfg = mld_vdb_vlan_get_cfg(vlan_node, create, afi);
    if (!cfg) 
	{
		if(create)
        	L2MCD_LOG_INFO("%s %d cfg could not malloc %d %d",
							__FUNCTION__, __LINE__, vlan_node->ivid, create);
        return (NULL);
    }

	if (!is_ve) 
	{
		if (!cfg->l2_static_group_list)
		{
			if(create)
			{
				cfg->l2_static_group_list = list_new();
			}
			else
				return (NULL);
		}
		return (cfg->l2_static_group_list);
	} else {
		if (!cfg->l3_static_group_list)
		{
			if(create)
			{
				cfg->l3_static_group_list = list_new();
			}
			else
				return (NULL);
		}
		return (cfg->l3_static_group_list);
	}
}


int mld_portdb_gvid_key_compare(unsigned long key1, unsigned long key2)
{
    if (key1 < key2)
        return -1;
    else if (key1 > key2)
        return 1;
    return 0;
}

int mld_portdb_gvid_hash_function(unsigned long key)
{
    return key; 
}

int mld_portdb_gvid_hash_init(void)
{
    mld_portdb_gvid_to_ivid_hash = hashGrowGenericCreate(
			MLD_PORTDB_GVID_HASH_INIT_SIZE,
            HASH_GROW_DO_NOT_SHRINK, (
			int (*)(unsigned long, unsigned long))mld_portdb_gvid_key_compare,
            (UINT32 (*)(unsigned long))mld_portdb_gvid_hash_function, NULL);
    if (!mld_portdb_gvid_to_ivid_hash) 
	{
		L2MCD_LOG_ERR("%s mld_portdb_gvid_to_ivid_hash alloc fail", __FUNCTION__);
	}
    return 0;
}

int mld_portdb_add_gvid(unsigned long gvid, unsigned long ivid)
{
    int ret;
    ret = hashGrowGenericInsert(mld_portdb_gvid_to_ivid_hash, gvid, (unsigned long)ivid);
    if(!ret) return -1; //Failed to add gvid to hash table;
	L2MCD_LOG_INFO("%s %d %d", __FUNCTION__, gvid, ivid);
    return 0;
}

int mld_portdb_delete_gvid(unsigned long gvid)
{
	return 0;
    #if 0
    unsigned int ivid_ptr = 0;
    ret = hashGrowGenericGetAndDelete(mld_portdb_gvid_to_ivid_hash, gvid, (unsigned long *)&ivid_ptr, NULL);
	L2MCD_LOG_INFO("%s(%d) ret :%d ", FN, LN, ret);
    #endif
}

unsigned int mld_portdb_get_ivid_from_gvid(uint32_t vlan_id,uint8_t type)
{
   
    mld_vlan_node_t *vlan_node = NULL;
    vlan_node = mld_vlan_node_get(vlan_id);
    if(!vlan_node) {
        goto vdb_dpv_done;
    }
    return vlan_node->ivid;

vdb_dpv_done:
    return (-1);
}

void
print_mrtr_list(mld_vlan_node_t *vlan_node, uint8_t afi)
{

	struct list *mrtr_list = NULL;
	mld_mrtr_t  *mrtr = NULL;
	struct listnode *list_node;

    L2MCD_CLI_PRINT("\t Multicast Router ports:");
	mrtr_list  = mld_vdb_vlan_get_mrtr_list(vlan_node, FALSE , afi);
    LIST_LOOP(mrtr_list, mrtr, list_node)
	{
		L2MCD_CLI_PRINT("\t	%s ", mrtr->ifname);
	}
}

mld_vlan_node_t *
mld_vlan_create_fwd_ref(uint32_t gvid,uint8_t type)
{
    mld_vlan_node_t *vlan_node = NULL;
    char  tmp_if_name[INTERFACE_NAMSIZ];
	char *ifname = NULL;
	int port;

	/* for router port ifindex is considered as gvid */
    L2MCD_LOG_INFO("%s(%d) gvid = %u", __FUNCTION__, __LINE__, gvid);
	if (gvid < MLD_MAX_VLANS) 
    {
        if(type == MLD_VLAN)
        {
			GET_MLD_VLAN_NAME(tmp_if_name, gvid);
        } else { 
			GET_MLD_VLAN_NAME(tmp_if_name, gvid);
        }
	}
	else 
	{
		port = mld_l3_get_port_from_ifindex(gvid,type);
		ifname = portdb_get_ifname_from_portindex(port); 
		if (ifname != NULL) {
			strncpy(tmp_if_name, ifname, (INTERFACE_NAMSIZ-1)); 
		}
		else {
			L2MCD_LOG_INFO("%s(%d) ERROR: gvid: %d (0x %x) ifname_from_portindex return NULL. ", __FUNCTION__, __LINE__, gvid, gvid );	
			memset(tmp_if_name, 0, INTERFACE_NAMSIZ-1);
            return NULL;
		}
	}

    vlan_node = mld_vdb_vlan_create(mld_vlan_get_db(), gvid, type, 0,
                                            0, 0, tmp_if_name, MLD_VLAN_DCM);
    L2MCD_LOG_INFO("%s(%d) new vlan_node created for gvid : 0x%x ", __FUNCTION__, __LINE__, gvid);
	return (vlan_node);
}

int mld_unset_vlan_dcm_flag(uint32_t gvid,uint8_t type)
{
    mld_vlan_node_t *vlan_node = NULL;
    vlan_node = mld_vdb_vlan_get(gvid,type);
    if (vlan_node) UNSET_FLAG(vlan_node->rcvd_nsm_add, MLD_VLAN_DCM);
	return (0);
}

int mld_set_vlan_dcm_flag(uint32_t gvid,uint8_t type)
{
    mld_vlan_node_t *vlan_node = NULL;

    vlan_node = mld_vdb_vlan_get(gvid,type);
    if(vlan_node)
        SET_FLAG(vlan_node->rcvd_nsm_add, MLD_VLAN_DCM);
	return 0;
}

void mld_vlan_delete_confg(mld_vlan_node_t *vlan_node)
{
    struct list * list;
    uint8_t afi;
    for( afi = 1; afi <= MCAST_AFI_MAX; afi++) {
        list = mld_vdb_vlan_get_mrtr_list(vlan_node, FALSE, afi);
        if(list) list_delete(list);
		/* Delete static group list of L2, L3 interface */
        list  = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, FALSE);
        if(list) list_delete(list);

		list = mld_vdb_vlan_get_static_grp_list(vlan_node, FALSE, afi, TRUE);
		if(list) list_delete(list);


        mld_free_cfg_param(vlan_node, afi);
        mld_free_cfg(vlan_node, afi);
    }
}

uint32_t mld_get_gvid(uint32_t ivid)
{
	unsigned long gvid;
	int err;
	err = mld_lookup_gvid_by_ivid(NULL, ivid, &gvid);
	if (err) gvid = 0;
	return (gvid);
}
