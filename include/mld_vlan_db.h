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

#ifndef __MLD_VLAN_DB_H__
#define __MLD_VLAN_DB_H__

#include "linklist_api.h"
#include "l2mcd_data_struct.h"
#include "l2mcd_mld_utils.h"
#include "mcast_addr.h"
#include "hash_grow_generic.h"
#include "igmp_struct.h"
#include "l2mcd_mcast_co.h"
#include "l2mcd.h"

/* Port and bitmap defines */
#define MLD_PORT_KEYLEN     (sizeof(ifindex_t) * 8)

typedef struct mld_cfg_param_s
{
    uint16_t            start_up_query_interval;
    uint16_t            start_up_query_count;
    uint16_t            cfg_query_interval_time;//query interval from usr cfg, init to dflt 125
    uint16_t            max_response_time;
    uint16_t            group_membership_time;
    uint16_t            older_host_present_time;
    uint16_t            LMQ_interval;          // last_member_query_interval
    uint8_t             LMQ_count;         // last_member_query_count
    uint8_t             cfg_robustness_var;
	uint8_t             cfg_version;
}mld_cfg_param_t;

typedef struct mld_cfg_s
{
	mld_cfg_param_t *param;
	struct list   *l2_static_group_list;
	struct list   *l3_static_group_list;
	struct list *mrtr_list;
}mld_cfg_t;

typedef struct mld_mrtr_s
{
	char ifname[INTERFACE_NAMSIZ + 1];	
}mld_mrtr_t;

typedef  struct mld_vlan_port_s {
    L2MCD_AVL_NODE node;
    uint32_t ifindex;
    uint8_t  lif_state;
}mld_vlan_port_t;

typedef struct mld_vlan_node_s {
    L2MCD_AVL_NODE node;
    ifindex_t ifindex;      /* For interface L2/L3 subsystems */
	ifindex_t ve_ifindex;	/* Binded VE interface */
    uint32_t gvid;           /* VLAN ID as calculated by MLD */
	uint16_t ivid;
    uint32_t flags[2];
	uint32_t vlan_flags;
	uint32_t    multi_access_ntwrk_flag; /* Member set to 1 only if nbr count on vlan is more than 1 else 0*/
	uint8_t	 type;	/* ve or vlan or ve & vlan both */
	uint8_t	 rcvd_nsm_add;
	uint8_t	 cfg_version; // IGMPv1/v2/v3
	char	name[INTERFACE_NAMSIZ + 1];
	uint8_t	bmap_size;	
	/* These fields are maintaned for forward referencing case */
	mld_cfg_t	*mld_cfg[2];
	uint8_t mld_snp_by_usr[2];  /* mld/igmp snoop cfg by CLI */
	uint8_t pim_snp_by_usr[2]; /* PIMv4/v6 snoop cfg by CLI */
	L2MCD_AVL_TREE port_tree; /* Having ports as tree */
} mld_vlan_node_t;


/* Global structure that will act as the VLAN DB */
typedef struct mld_vlan_db_s {
    L2MCD_AVL_TREE  vdb_tree;
} mld_vlan_db_t;


/* Error value defines */
#define MLD_VLAN_DB_ERR_MAX -20

enum MLD_VLAN_DB_ERR_VALS {
    MLD_VLAN_DB_ENULL_PARAM = MLD_VLAN_DB_ERR_MAX,
    MLD_VLAN_DB_EPTREE_INIT,
    MLD_VLAN_DB_EPRTEE_ADD,
    MLD_VLAN_DB_ENOVLAN,
    MLD_VLAN_DB_ENOMEM,
    MLD_VLAN_DB_EMUTEX_INIT,
    MLD_VLAN_DB_SUCCESS = 0
};

#define MLD_VLAN_KEY_SIZE  5
#define MLD_VLAN_KEY_TYPE_OFFSET 0
#define MLD_VLAN_KEY_ID_OFFSET 1

/* APIs to access/set port bitmaps */
#define MLD_NO_MORE_PORTS      0xFFFFFFFF

#define MLD_INVALID_PARAM -2

#define MLD_VLAN_NSM (1 << 0) 
#define MLD_VLAN_DCM (1 << 1)

int mld_vdb_init(void);
//Create vlan_db entry
mld_vlan_node_t * mld_vdb_vlan_create(mld_vlan_db_t *vlan_db, uint32_t vlan_id, uint8_t type,
    uint32_t flags, uint32_t vlan_flags, uint16_t ivid, char *vlan_name, int vlan_creation_type);
//Delete VDB entry
int mld_vdb_vlan_del(mld_vlan_db_t *vlan_db, uint32_t vlan_id, uint8_t type);
//Add port to vdb port_tree
int mld_vdb_add_port_to_vlan(mld_vlan_db_t *vlan_db, uint32_t vlan_id, 
    uint32_t port_num, uint8_t type);
//Remove port from vdb port_tree
int mld_vdb_del_port_frm_vlan(mld_vlan_db_t *vlan_db, uint32_t vlan_id, 
    uint32_t port_num, uint8_t type);

void mld_free_cfg_param(mld_vlan_node_t *vlan_node, uint8_t afi);
void mld_free_cfg(mld_vlan_node_t *vlan_node, uint8_t afi);
uint8_t is_mld_vlan_snooping_enabled(mld_vlan_node_t *vlan, uint8_t afi);
void print_mrtr_list(mld_vlan_node_t *vlan_node, uint8_t afi);
void print_static_grp_list(mld_vlan_node_t *vlan_node, uint8_t afi);
void print_vlan_port_mbrship(mld_vlan_node_t *vlan_node);
void print_vlandb_details(mld_vlan_node_t *vlan_node);
void mld_poplate_bitmap(uint32_t *port_bitmap, uint32_t *ifindex_list, uint32_t size);
void mld_populate_ifindex_list(uint32_t *ifindex, uint32_t *bitmap, uint32_t *size);
unsigned int mld_portdb_get_ivid_from_gvid(uint32_t vlan_id, uint8_t type);
int mld_portdb_delete_gvid(unsigned long gvid);
int mld_portdb_add_gvid(unsigned long gvid, unsigned long ivid);
int mld_portdb_gvid_hash_init(void);
int mld_portdb_gvid_hash_function(unsigned long key);
int mld_portdb_gvid_key_compare(unsigned long key1, unsigned long key2);
struct list * mld_vdb_vlan_get_static_grp_list(mld_vlan_node_t *vlan_node, int create, uint8_t afi, BOOLEAN is_ve);
struct list *mld_vdb_vlan_get_mrtr_list(mld_vlan_node_t *vlan_node, int create, uint8_t afi);
mld_cfg_param_t *mld_vdb_vlan_get_cfg_param(mld_vlan_node_t *vlan_node, int create, uint8_t afi);
int is_mld_vlan_snooping_allowed(uint32_t vid, uint16_t vrfid, MCGRP_CLASS  *mld,
                                                             int glb_mode, uint8_t type );
uint8_t is_mld_vlan_l3_enabled(mld_vlan_node_t *vlan, uint8_t afi);
mld_vlan_node_t * mld_vdb_vlan_get(uint32_t vlan_id, uint8_t type);
uint32_t *mld_vdb_vlan_get_mrtr_bitmap(mld_vlan_node_t *vlan_node, int create, uint8_t afi);
mld_cfg_t *mld_vdb_vlan_get_cfg(mld_vlan_node_t *vlan_node, int create, uint8_t afi);
void mld_vlan_add_list(mld_vlan_node_t *vlan_p, uint8_t afi);
void mld_vlan_del_list(mld_vlan_node_t *vlan_p, uint8_t afi);
int mld_vdb_vlan_is_present_in_protocol(mld_vlan_node_t *vlan_node, uint8_t afi);
int mld_lookup_gvid_by_ivid(mld_vlan_node_t *vlan_node, uint16_t vlan_id, unsigned long *gvid);
uint8_t is_mld_snooping_enabled(MCGRP_L3IF *mcgrp_vport, uint8_t afi);
void mld_set_vlan_flag(mld_vlan_node_t *vlan_p, uint8_t afi, uint32_t flag);
void mld_unset_vlan_flag(mld_vlan_node_t *vlan_p, uint8_t afi, uint32_t flag);
uint32_t mld_is_flag_set(mld_vlan_node_t *vlan_p, uint8_t afi, uint32_t flag);
mld_vlan_node_t *mld_vlan_create_fwd_ref(uint32_t gvid, uint8_t type);
int mld_add_static_grp_node_to_pending_list(mld_vlan_node_t *vlan_node, mld_l2_static_group_t *input_msg, int add, BOOLEAN is_ve);
uint8_t mld_is_port_member_of_vlan(mld_vlan_node_t *vlan, uint32_t port_num);
void mld_vlan_delete_confg(mld_vlan_node_t *vlan_node);
void mld_intialize_with_def_values(mld_cfg_param_t * param);
uint8_t is_mld_l3_configured(MCGRP_L3IF *mcgrp_vport);
int mld_add_static_mrtr_to_pending_list(mld_vlan_node_t *vlan_node, 
							  char *if_name, int add, uint8_t afi);
extern mld_vlan_node_t *mld_get_vlan_by_ivid(UINT16 ivid);
mld_vlan_node_t *mld_vlan_node_get(uint32_t vid);
int mld_unset_vlan_dcm_flag(uint32_t gvid,uint8_t type);
int mld_set_vlan_dcm_flag(uint32_t gvid,uint8_t type);
mld_vlan_db_t * mld_vlan_get_db();
uint8_t is_mld_snooping_querier_enabled(MCGRP_L3IF *mcgrp_vport);
uint8_t is_mld_fast_leave_configured(MCGRP_L3IF *mcgrp_vport);
uint32_t mld_get_gvid(uint32_t ivid);
void mld_vlan_cleanup(mld_vlan_node_t *vlan);
#endif /* __MLD_VLAN_DB_H__ */

