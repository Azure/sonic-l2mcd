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

#ifndef __L2MCD_MCAST_CO__
#define __L2MCD_MCAST_CO__

#include "l2mcd.h"
#include "mcast_addr.h"
#include "igmp_struct.h"
#include "wheel_timer.h"

#define MAX_SLOT                    1
#define GET_MAX_PORT()				256
#define MAX_MC_INTFS L2MCD_MAX_INTERFACES

#define MCAST_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index) (((vrf_index) > IPVRF_MAX_VRF_IDX) ? NULL : ((afi) == IP_IPV4_AFI ? gMulticast.instances[vrf_index] : NULL))


#define MCGRP_GET_INSTANCE_FROM_VRFINDEX(afi, vrf_index) \
			(((vrf_index) > IPVRF_MAX_VRF_IDX) ? NULL \
												: ((afi) == IP_IPV4_AFI ? gIgmp.instances[vrf_index] \
												: gMld.instances[vrf_index]))					
#define IGMP_GET_INSTANCE_FROM_VRFINDEX(vrf_index) (((vrf_index) > IPVRF_MAX_VRF_IDX) ? NULL : gIgmp.instances[vrf_index])
#define MLD_GET_INSTANCE_FROM_VRFINDEX(vrf_index) (((vrf_index) > IPVRF_MAX_VRF_IDX) ? NULL : gMld.instances[vrf_index])


#define PORT_MASK_ARRAY_SIZE   5 
typedef struct { unsigned long ul[PORT_MASK_ARRAY_SIZE]; } PORT_MASK;

#define PORT_MASK_ZERO(portmask)\
	memset((char*)&portmask,0,sizeof(PORT_MASK))

struct MCAST_SOURCE_INFO
{
	struct MCAST_SOURCE_INFO* next;
	MADDR_ST  src_addr;
};

typedef struct MCAST_SOURCE_INFO MCAST_SOURCE_INFO;

typedef struct GROUP_ENTRY
{
	L2MCD_AVL_NODE   node;
	MADDR_ST      group_address;
} GROUP_ENTRY;

#define IGMP_MAX_ACTION_TYPE      6
// There is some code that uses the IGMPV3 version of enums
// while the IGMP code uses the enums w/o the IGMPV3 prefix
enum IGMPV3_ACTION
{
	IS_INCL      = 1,
	IGMPV3_IS_IN = 1,

	IS_EXCL      = 2,
	IGMPV3_IS_EX = 2,

	TO_INCL      = 3,
	IGMPV3_TO_IN = 3,

	TO_EXCL      = 4,
	IGMPV3_TO_EX = 4,

	ALLOW_NEW    = 5,
	IGMPV3_ALLOW = 5,

	BLOCK_OLD    = 6,
	IGMPV3_BLOCK = 6
};

/* All time values are in seconds */
#define	IGMP_DEFAULT_ROBUSTNESS_VARIABLE				2
#define IGMP_DEFAULT_QUERY_RESPONSE_INTERVAL_TIME		10
#define	IGMP_DEFAULT_QUERY_INTERVAL_TIME				125

// Other GroupMmbrship Time = RobustnessVar * QueryIntvlTime + QueryResponseIntvl
#define IGMP_DEFAULT_GROUP_MEMBERSHIP_TIME 				\
		(IGMP_DEFAULT_ROBUSTNESS_VARIABLE * IGMP_DEFAULT_QUERY_INTERVAL_TIME) + IGMP_DEFAULT_QUERY_RESPONSE_INTERVAL_TIME

enum IGMP_PDUTYPE
{
	IGMP_MEMBERSHIP_QUERY_TYPE		= 0x11,
	IGMP_V1_MEMBERSHIP_REPORT_TYPE	= 0x12,
	IGMP_V2_MEMBERSHIP_REPORT_TYPE	= 0x16,
	IGMP_V2_LEAVE_GROUP_TYPE		= 0x17,
	IGMP_V3_MEMBERSHIP_REPORT_TYPE	= 0x22
};

#define IPVRF_MAX_USER_DEFINED_VRFS      1024
#define MVRF_DEFAULT_VRF_ID  L2MCD_DEFAULT_VRF_IDX
#define IPVRF_MAX_VRF_IDX                (IPVRF_MAX_USER_DEFINED_VRFS + 1)
#define IPVRF_INVALID_VRF_IDX		(IPVRF_MAX_VRF_IDX+1)
#define IPVRF_DEFAULT_VRF_IDX		     MVRF_DEFAULT_VRF_ID

#define INVALID_BMP					0xFFFFFFFF
#define PIM_ENCODE_SRC_ADDRESS_WC (0)

#define MLD_SNOOPING_GLB_ENABLED  0x2
#define MLD_SNOOPING_NO_FLOOD_ENABLED 0x4
#define MLD_VE_ENABLED		0x8
#define MLD_FAST_LEAVE_CONFIGURED  0x10
#define MLD_SNOOPING_QUERIER_ENABLED 0x20
#define MLD_VE_PIM_ENABLED 0x40 
#define MLD_START_UP_QUERY_COUNT_CONFIGURED 0x80
#define MLD_LMQC_CONFIGURED 0x100
#define MLD_VLAN_DELETED 0x200
#define MLD_VLAN_HOP_BY_HOP_TRAP_CONFIGURED 0x400
#define MLD_START_UP_QUERY_INTERVAL 0x800
#define NO_SUCH_PORT			0xFFFF
#define PIMS_MAX_VLAN_SUPPORT_REACHED 500
#define DEFAULT_MROUTER_AGING_TIME 300  //in seconds
#define CU_DFLT_IGMP_QUERY_INTERVAL             IGMP_DEFAULT_QUERY_INTERVAL_TIME
#define CU_DFLT_IGMP_RESPONSE_TIME              IGMP_DEFAULT_QUERY_RESPONSE_INTERVAL_TIME
#define CU_DFLT_IGMP_GROUP_MEMBERSHIP_TIME      260
#define CU_DFLT_IGMP_OLDER_HOST_PRESENT_TIME	IGMP_DEFAULT_GROUP_MEMBERSHIP_TIME
#define CU_DFLT_IGMP_LLQI						1
#define CU_DFLT_LLQI_IN_MSEC                    (CU_DFLT_IGMP_LLQI * 1000)

/* MLD Flags for struct MCGRP_L3IF */															
#define MLD_IF_CFLAG_LAST_MEMBER_QUERY_COUNT       (1 << 7)
#define MLD_IF_CFLAG_LAST_MEMBER_QUERY_INTERVAL    (1 << 8)
#define MLD_IF_CFLAG_LIMIT_GREC                    (1 << 9)
#define MLD_IF_CFLAG_QUERIER_TIMEOUT               (1 << 10)
#define MLD_IF_CFLAG_QUERY_INTERVAL                (1 << 11)
#define MLD_IF_CFLAG_QUERY_RESPONSE_INTERVAL       (1 << 12)
#define MLD_IF_CFLAG_ROBUSTNESS_VAR                (1 << 13)
#define MLD_SNOOPING_ENABLED					   (1 << 14) /* This flag is set when MLD snooping is implicitly/explicitly
                                                                enabled on an interface. */
#define MLD_SNOOPING_DISABLED                      (1 << 15) /* It means that MLD snooping has been implicitly/explicitly disabled on an interface.
																When this flag is set on an interface, If user configures global snooping 
                                                                enable then snooping wont be enabled on this interface.*/
																 
#define MLD_IF_CFG_SNOOP_STARTUP_QUERY_INTERVAL  (1 << 20)
#define MLD_IF_CFLAG_SNOOP_STARTUP_QUERY_COUNT     (1 << 21)
#define MLD_SNP_ADDED_PROTOCOL						(1 << 23)
/* PIM snooping flags */
#define MLD_PIM_SNOOP_ENABLED                       (1 << 24)
#define MLD_PIM_SNOOP_DISABLED                       (1 << 25)
/* Below flags will be set when user explicitly configure snooping under vlan */
#define MLD_IF_CFLAG_SNOOPING_ENABLED                        (1<<26)
#define MLD_IF_CFLAG_SNOOPING_DISABLED                       (1<<27) 

#define DEFAULT_VRF_NAME    "default-vrf"
#define DEFAULT_VRF_ID      MVRF_DEFAULT_VRF_ID

#define L2MCD_SYNC_IGMP_SNP_GLB_CLR  (1 << 0)

#define		DISABLE				0
#define		ENABLE				1
#define CU_DFLT_IGMP_ROBUSTNESS					2
#define CU_DFLT_MLD_ROBUSTNESS					CU_DFLT_IGMP_ROBUSTNESS

#define MAX_L3_PORTS 1024
#define IGMP_MAX_IPC_SIZE (1024 * 28)

#define MCGRP_MAX_TIME_SLOTS                260
#define MAX_MCGRP_INTFS			L2MCD_MAX_INTERFACES

#define IP_MINIMUM_HEADER_LENGTH_BYTE					20
#define IP_ROUTER_ALERT_OPTION_LENGTH			4
#define     IP_MINIMUM_HEADER_LENGTH        20
#define IP_VERSION_NUMBER								4

#define IP_IGMPV3_REPORT_ADDRESS							0xE0000016	/* 224.0.0.22 */
#define	IP_ALL_NODES_MULTICAST_ADDRESS						0xE0000001
#define IP_ALL_ROUTERS_MULTICAST_ADDRESS					0xE0000002

#define CU_DFLT_IGMP_MAX_GROUP_ADDRESS			4096
#define CU_DFLT_MLD_MAX_GROUP_ADDRESS			CU_DFLT_IGMP_MAX_GROUP_ADDRESS
#define INVALID_TRUNK_ID				( 0 )
#define MCGRP_VERSION_WARN_RATE             1
typedef UINT32 TRUNK_ID;

#define trunk_primary_port(port) port
#ifndef MASK2PREFIX_LENGTH
#define MASK2PREFIX_LENGTH(mask) (mask2prefix_map[mask%37])
#endif 

#define IS_IGMP_CLASS(mcgrp)     ((mcgrp)->afi == IP_IPV4_AFI ? TRUE : FALSE)
#define IS_MLD_CLASS(mcgrp)      ((mcgrp)->afi == IP_IPV6_AFI ? TRUE : FALSE)

#define INVALID_BMP					0xFFFFFFFF
#define BITS_PER_BYTE				8
#define BYTES_PER_WORD				4
#define BITS_PER_WORD				(BITS_PER_BYTE * BYTES_PER_WORD)
#define BMP_WORDS(bit_count)    	(((bit_count)+31)/BITS_PER_WORD)

#if __BYTE_ORDER  == __LITTLE_ENDIAN
#define SET_BIT_WORD(_w_, _bit_)	((_w_)|=(0x00000001<<(_bit_)))
#define RESET_BIT_WORD(_w_, _bit_)	((_w_)&=~(0x00000001<<(_bit_)))
#define IS_BIT_SET_WORD(_w_, _bit_)	(((_w_)&(0x00000001<<(_bit_)))?1:0)
#define SET_BIT_BYTE(_b_, _bit_)	((_b_)|=(0x01<<(_bit_)))
#define RESET_BIT_BYTE(_b_, _bit_)	((_b_)&=~(0x01<<(_bit_)))
#define IS_BIT_SET_BYTE(_b_, _bit_)	(((_b_)&(0x01<<(_bit_)))?1:0)
#else
#define SET_BIT_WORD(_w_, _bit_)	((_w_)|=(0x80000000>>(_bit_)))
#define RESET_BIT_WORD(_w_, _bit_)	((_w_)&=~(0x80000000>>(_bit_)))
#define IS_BIT_SET_WORD(_w_, _bit_)	(((_w_)&(0x80000000>>(_bit_)))?1:0)
#define SET_BIT_BYTE(_b_, _bit_)	((_b_)|=(0x80>>(_bit_)))
#define RESET_BIT_BYTE(_b_, _bit_)	((_b_)&=~(0x80>>(_bit_)))
#define IS_BIT_SET_BYTE(_b_, _bit_)	(((_b_)&(0x80>>(_bit_)))?1:0)
#endif 

#define SET_BIT_BMP(_bmp_, _bit_)											\
        (SET_BIT_WORD((((uint32_t *)(_bmp_))[(_bit_)/BITS_PER_WORD]),		\
		 (_bit_)%BITS_PER_WORD))

#define RESET_BIT_BMP(_bmp_, _bit_)											\
        (RESET_BIT_WORD((((uint32_t *)(_bmp_))[(_bit_)/BITS_PER_WORD]), 	\
		 (_bit_)%BITS_PER_WORD))

#define IS_BIT_SET_BMP(_bmp_, _bit_)										\
        (IS_BIT_SET_WORD((((uint32_t *)(_bmp_))[(_bit_)/BITS_PER_WORD]),	\
		(_bit_)%BITS_PER_WORD))

#define BMP_CLRALL(_bmp_, _numBytes_)										\
		(memset((_bmp_), '\0', _numBytes_))

#define IPV4_MAX_BYTELEN    4
#define IPV4_ADDR_SAME(D,S)  (memcmp ((D), (S), IPV4_MAX_BYTELEN) == 0)

extern unsigned long g_timebase_freq;
extern unsigned long long read_long_time_base();
extern UINT32 mcgrp_get_remaining_time(WheelTimerId timer_id, WheelTimerElement *timer_elem);
extern UINT8 mcgrp_val2code (UINT16 val);
extern int l3_get_max_ports(void);
extern unsigned int portdb_get_port_vrf_index(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);

#define G_1SEC_TB		(g_timebase_freq)
#define G_100MSEC_TB		(g_timebase_freq/10)
#define G_50MSEC_TB		(g_timebase_freq/20)
#define G_40MSEC_TB		(g_timebase_freq/25)
#define G_30MSEC_TB		(g_timebase_freq/33)
#define G_20MSEC_TB		(g_timebase_freq/50)
#define G_10MSEC_TB		(g_timebase_freq/100)
#define G_5MSEC_TB		(g_timebase_freq/200)
#define G_2MSEC_TB		(g_timebase_freq/500)
#define G_MSEC_TB		(g_timebase_freq/1000)
#define g_msec		G_MSEC_TB

#define IS_IPV6_ADDRESS_NON_ZERO(ipv6_addr) ((  (ipv6_addr.address.address32[0] != 0) || \
            (ipv6_addr.address.address32[1] != 0) || \
            (ipv6_addr.address.address32[2] != 0) || \
            (ipv6_addr.address.address32[3] != 0) ) ? 1 : 0 )

extern unsigned char portdb_is_port_index_valid(L2MCD_AVL_TREE *portdb_tree, unsigned int port_index);

typedef struct MLD_PORT_MASK
{
	UINT8		bitmap[0];
}MLD_PORT_MASK;

// Wheel timer definition
typedef enum MCGRP_TIMER_TYPE
{
	MCGRP_WTE_STATIC,
	MCGRP_WTE_QUERIER,
	MCGRP_WTE_MBRSHP,
	MCGRP_WTE_LMQI,
	MCGRP_WTE_CLIENT,
	MCGRP_WTE_L2_STATIC,
    MCGRP_WTE_MROUTER,
	MCGRP_WTE_SRC_MBRSHP,
    MCGRP_WTE_MCT_LEAVE_SYNC_MAX_RESP_TMR,
} MCGRP_TIMER_TYPE;

#define MCAST_INSERT_SOURCE 6

typedef enum IP_AFI_TYPES
{
	IP_IPV4_AFI	= 0x0001,
	IP_IPV6_AFI	= 0x0002,
	IP_AFI_SIZE	= 2
} IP_AFI_TYPES;

typedef enum 
{
	TRUNK_NONE = 0,
	TRUNK_PRIMARY,
	TRUNK_SECONDARY
} TRUNK_STATE;

typedef enum MCGRP_FILTER_MODE
{
	FILT_INCL = 0,
	FILT_EXCL = 1
} MCGRP_FILTER_MODE;

#define FILT_PIMS	(FILT_EXCL + 1)
typedef enum MCGRP_MBRSHIP_RETURN_CODE
{
    MCGRP_NO_MBRHSHIP   = 0,
    MCGRP_SG_MBRSHIP_EXISTS = 1,
    MCGRP_SG_INCLUDE   = 2,
    MCGRP_SG_EXCLUDE   = 3,
    MCGRP_EXCLUDE_NONE = 4
} MCGRP_MBRSHIP_RETURN_CODE;

enum MCGRP_GRP_ACTION
{
    MCGRP_ADD_GROUP = 0,
    MCGRP_DELETE_GROUP = 1
};

#define IP_ROUTER_ALERT_OPTION 20
#define  IGMP_PROTOCOL 2
#define IP_ROUTER_ALERT_OPTION_TYPE 148

typedef struct sg_port_s {
    L2MCD_AVL_NODE node;
    uint32_t ifindex;
} sg_port_t;

typedef struct PSEUDO_IP_PARAMETERS
{
	ULONG 		source_address;
	ULONG 		destination_address;
	BYTE		zero_field;
	BYTE 		protocol;
	USHORT 		length;
} PSEUDO_IP_PARAMETERS;

typedef struct MCGRP_TMR_ELEM_CLNT
{
	L2MCD_AVL_TREE            *clnt_tree;
	struct s_MCGRP_CLIENT  *mcgrp_clnt;
} MCGRP_TMR_ELEM_CLNT;

typedef	struct  MCGRP_ENTRY
{
	L2MCD_AVL_NODE     node;
	MADDR_ST        group_address;
	UINT32          num_mbr_ports;
	struct MCGRP_MBRSHP*   mbr_port;
	L2MCD_AVL_TREE     mbr_ports_tree;

	BOOLEAN	        is_ssm;
	UINT16 pims_num_wg_join_ports;
	UINT16 pims_num_sg_join_ports;
	UINT32 pims_num_wg_joins_rcvd;
	UINT32 pims_num_sg_joins_rcvd;
	UINT32 pims_num_wg_prunes_rcvd;
	UINT32 pims_num_sg_prunes_rcvd;
} MCGRP_ENTRY;


typedef struct MCGRP_TMR_ELEM_MBRSHP
{
	struct MCGRP_MBRSHP *mcgrp_mbrshp;
	struct MCGRP_L3IF   *vport;
	struct MCGRP_ENTRY  *grp_entry;
	struct s_MCGRP_SOURCE *pims_src_entry;
} MCGRP_TMR_ELEM_MBRSHP;

typedef struct MCGRP_TMR_ELEM_QUERIER
{
	struct MCGRP_L3IF *mcgrp_vport;
} MCGRP_TMR_ELEM_QUERIER;

typedef struct MCGRP_TMR_ELEM_MROUTER
{
   struct MCGRP_L3IF *mcgrp_vport;
   UINT32             phy_port_id;

} MCGRP_TMR_ELEM_MROUTER;

typedef struct MCGRP_TIMER_ELEM
{
	WheelTimerElement    mcgrp_wte;
	MCGRP_TIMER_TYPE     timer_type;
	struct MCGRP_CLASS  *mcgrp;
	union
	{
		struct MCGRP_TMR_ELEM_CLNT       clnt;
		struct MCGRP_TMR_ELEM_MBRSHP     mbrshp;
		struct MCGRP_TMR_ELEM_QUERIER    pport;
		struct MCGRP_STATIC_ENTRY       *static_grp;
		struct MCGRP_TMR_ELEM_QUERIER    vport;
		struct MCGRP_STATIC_ENTRY        *l2_static_grp;
        struct MCGRP_TMR_ELEM_MROUTER    mrtr_port;
	} wte;
} MCGRP_TIMER_ELEM;


typedef struct s_MCGRP_SOURCE
{
	// Please retain the order of next, src_addr
	// This enables us to use a IGMPV#_SOURCE as a SORTED_LINKLIST node
	struct s_MCGRP_SOURCE* next;
	MADDR_ST               src_addr;
	UINT64                 src_timer; //RD:change it Uint 32.
	UINT8                  retx_cnt;
	UINT8                  include_in_query;
    UINT8                  is_remote;
	// List of clients for this source
	L2MCD_AVL_TREE            clnt_tree;
	void                  *igmp_mld;   // This is used mainly by igmpv3/mldv2_src_destroy().
	MCGRP_TIMER_ELEM 	pims_src_tmr;	/* SG timer */
	UINT32 				pims_num_sg_joins_rcvd;
	UINT32 				pims_num_sg_prunes_rcvd; /* This counter is incremented due to  S,G RptPrune received */
	UINT16				hold_time;
	UINT8				rpt_flag; /* This flag indicates that the S,G is created due to RptPrune message received */
	UINT64              src_uptime;	// time the node got created
	UINT8				sg_rpt_rx_flag;
} MCGRP_SOURCE;

/* This structure represents a physical port's membership in a group
 * These structures are chained off of a group node which in turn hangs off
 * of an IP inrerface entry.
 * Typically, there shall be one structure per group per interface, except
 * where the interface is a VE, in which case, there shall be one such
 * structure for every physical port in the VE that is an active IGMP 
 * participant in the group.
 */
typedef struct MCGRP_MBRSHP
{
	UINT32            phy_port_id;
	L2MCD_AVL_NODE       node;
	UINT8             retx_cnt;

	UINT8             static_mmbr     : 1;
	UINT8             filter_mode     : 1;     // 0 - INCLUDE; 1 - EXCLUDE
	UINT8             aging_enabled   : 1;     // aging enabled for this membership
	UINT8             grp_compver     : 2;     // minimum host Version seen on this port
	UINT8             is_remote       : 1;     //Remote Entry, eg: Synced from MCLAG peer
	UINT8             spare           : 1;


	UINT64            host_present[NUM_IGMP_VERSION+1];  //RD:change it to UINT32.

	// INCLUDE/ EXCLUDE list of sources for this group on this port
	MCGRP_SOURCE*     src_list[2];

	// List of clients for this group on this port
	L2MCD_AVL_TREE       clnt_tree;

	// Wheel timer element
	MCGRP_TIMER_ELEM  mbrshp_tmr;
	MCGRP_TIMER_ELEM  lmq_tmr;
	UINT64            group_timer; 
	UINT64            lmq_timer; //timestamp for src list
	UINT64            group_uptime;
	/* This is for sending client leave to mrouter  ports, if within expiry , 
 	*  switch does not recieve the response on this port */
		
	MADDR_ST        client_source_addr;
	MADDR_ST        last_reporter_ip_addr;
	/* PIM snoop specific */
	MCGRP_SOURCE* 	pims_src_list;
	UINT8 			pims_mbr_flags;	/* wg or sg  */
	UINT16			hold_time;
} MCGRP_MBRSHP;

typedef	struct MCGRP_STATIC_ENTRY
{
	// WARNING: ****
	//	
	// Casted to LINKLIST_TYPE and hence next MUST be the first element
	//
	struct MCGRP_STATIC_ENTRY *next;
	MADDR_ST                   group_address;
	PORT_ID	                   port_num;                    /* port number in ve level */
	UINT8                      flags;
	UINT8                      spare;
	L2MCD_AVL_TREE				    port_tree;
	// Wheel timer element for l2 static group
	MCGRP_TIMER_ELEM			l2_static_grp_tmr;	
	// Wheel timer element
	MCGRP_TIMER_ELEM    static_grp_tmr;
} MCGRP_STATIC_ENTRY;

/* This data structure represents IGMP/MLD's state on each IP interface */
typedef struct MCGRP_PORT_ENTRY
{
	struct MCGRP_PORT_ENTRY*  next;   // For VE ports, this give the next elem
	                                  // For physical ports it is NULL 
	UINT32            phy_port_id;
	UINT16            start_up_query_count;

	/* IP address of the querier on this port;
	 * If we are querier, it will be this port's IP address */
	MADDR_ST          querier_router;

	UINT16            querier           : 1;    // Are we querier on this port ?
	UINT16            is_up             : 1;
	UINT16            has_static_grps   : 1;

	// Configured values
	UINT16            cfg_mcast_disable : 1;
	UINT16            cfg_version       : 2;    // configured version, if any (0,1,2 or 3 )
	UINT16            oper_version      : 2;    // Version we are operating at (1,2 or 3)
	UINT16            v1_rtr_present    : 1;    // Did we hear from a V1 router ?
	UINT16            v2_rtr_present    : 1;    // Did we hear from a V2 router ?
	UINT16            spare             : 6;
	UINT32            verwarn_intvl_start;      // Can we add a syslog...msg for this????
	UINT32            verwarn_count;
	BOOLEAN			snooping_mrouter_detected;
} MCGRP_PORT_ENTRY ;

/* This data structure represents IGMP/MLD's state on each IP interface */
typedef struct MCGRP_ROUTER_ENTRY
{
    struct MCGRP_ROUTER_ENTRY*  next;   // For VE ports, this give the next elem
                                      // For physical ports it is NULL
    UINT32            phy_port_id;
    UINT32            verwarn_intvl_start;      // Can we add a syslog...msg for this????
    UINT32            verwarn_count;
    UINT32            is_static : 1; //static or dynamic mrouter
	UINT16            cfg_version       : 2;    // configured version, if any (0,1,2 ) 
	UINT64            uptime;
    MCGRP_TIMER_ELEM  mrtr_tmr;
	UINT8           type;
	UINT16			time;
}MCGRP_ROUTER_ENTRY;

typedef struct MCGRP_L3IF
{
	MCGRP_PORT_ENTRY*  phy_port_list;   // List of physical member ports
	L2MCD_AVL_TREE        sptr_grp_tree;   //AVL Tree of MCGRP_ENTRY(per group)

	UINT32             ngroups;
	UINT32             phy_port_id;
	UINT16             vir_port_id;
	UINT8              type;

	UINT8              is_ve             : 1;    // Port part of a VE interface ?
	UINT8              cfg_mcast_disable : 1;
	UINT8              cfg_version       : 2;    // configured version, if any (0,1,2 or 3 )
	UINT8              oper_version      : 2;    // Version we are operating at (1,2 or 3)
	UINT8              tracking_enabled  : 1;
	UINT8              is_up             : 1;
    UINT16            start_up_query_interval;
    UINT16            start_up_query_count;
    UINT16            query_interval_time;    // actual query interval used
    UINT16            cfg_query_interval_time;//query interval from usr cfg, init to dflt 125 
    UINT16            max_response_time;
    UINT32            group_membership_time;
    UINT16            older_host_present_time;
    UINT16            LMQ_interval;          // last_member_query_interval
    UINT8             LMQ_count;         // last_member_query_count
    UINT8             LMQ_100ms_enabled; // last_member_query_flag
    UINT8             cfg_robustness_var;
    UINT8             robustness_var;

    /* IP address of the querier on this port;
     * If we are querier, it will be this port's IP address */
    MADDR_ST          querier_router;
    UINT16            querier           : 1;    // Are we querier on this port ?
    UINT64            querier_uptime;

    // Wheel timer element
    MCGRP_TIMER_ELEM  vport_tmr;
    UINT16            v1_rtr_present    : 1;    // Did we hear from a V1 router ?
    UINT16            v2_rtr_present    : 1;    // Did we hear from a V2 router ?
	MLD_PORT_MASK*		ve_port_mask;	
	MCGRP_STATIC_ENTRY* static_mcgrp_list_head;
	MCGRP_ROUTER_ENTRY* rtr_port_list;
    UINT32            verwarn_intvl_start;      // Can we add a syslog...msg for this????
    UINT32            verwarn_count;
	UINT32			   flags;
	UINT8				is_l3_up;	/* For running protocol as part of l2 , doing is_up whenever vlan is added, 
									*  to explicitly know about l3 up status, will be using this , in future 
									*/	
	BOOLEAN			pims_enable;	/* PIM snooping enabled flag */
	UINT32 			pims_num_wg_entries;
	UINT32          pims_num_sg_entries;
    // Statistics   
    UINT32               rx_bad_if;
   
} MCGRP_L3IF;

typedef struct MCGRP_CLASS
{
	struct MCGRP_CLASS	*inst_fwd;
	struct MCGRP_CLASS	*inst_bwd;
	VRF_INDEX            vrf_index;

	UINT16               query_interval_time;    // actual query interval used
	UINT16               cfg_query_interval_time;//query interval from usr cfg, init to dflt 125 
	UINT16               max_response_time;
	UINT16               group_membership_time;
	UINT16               older_host_present_time;
	UINT16               LMQ_interval;          // last_member_query_interval
	UINT16               static_group_timer;
	UINT8	             cfg_robustness_var;
	UINT8                robustness_var;
	UINT8                enabled;
	UINT8                LMQ_count;         // last_member_query_count
    UINT8                LMQ_100ms_enabled; // last_member_query_flag
	UINT8                cfg_version;       // configured version, if any (0,1,2 or 3)
	
	UINT8                oper_version;      // version we are operating at (1,2 or 3)
	UINT32               afi;               //v4 or v6 family
	IGMP_STATS          *igmp_stats;  //RD: Make it common.
	MLD_STATS           *mld_stats;
	BOOLEAN				 router_alert_check_disable; /*Flag to disable checking the router alert option in IGMP packets*/
	MCGRP_STATIC_ENTRY  *static_mcgrp_list_head;

	UINT32               pim_prune_wait_interval; // Prune wait inetrval of pim.
	UINT32	             max_groups;
    UINT16               first_time_init;

	//Global Wheel Timer
	WheelTimerId         mcgrp_wtid;
	//Global Wheel Timer for LMQ Interval
	WheelTimerId         mcgrp_wtid_lmq;
	// Statistics	
	UINT32               rx_bad_if;

	//IGMPv3 & SSM MAP
	L2MCD_AVL_TREE			 group_tree;
	UINT32				 ngroups;
} MCGRP_CLASS;


typedef struct MCGRP_GLOBAL_CLASS
{
	MCGRP_CLASS    	        *instances[IPVRF_MAX_VRF_IDX+1];
	MCGRP_CLASS             *instances_list; /*List of actual configured instances*/
	MCGRP_L3IF             **port_list;
   
	SORTED_LINKLIST_KEYINFO *mcgrp_src_keyinfo;
	// klin, change to growable pool
	generic_pool_struct     *group_pool;
	generic_pool_struct     *grp_mbrshp_pool;
	generic_pool_struct     *src_specific_pool;
	generic_pool_struct     *src_specific_client_pool;
    BOOLEAN             g_snooping_enabled;
	BOOLEAN				no_flood_enabled;
    L2MCD_AVL_TREE         portdb_tree; //Mainly for ipv6 addresses and port_state
	L2MCD_AVL_TREE         ve_portdb_tree; //Used for Ve port 
	UINT8				mac[6];
    UINT8                cfg_version;       // configured version, if any (0,1,2 or 3)
    UINT8                oper_version;      // version we are operating at (1,2 or 3)
	generic_pool_struct  *vlan_pool;
    UINT32              mld_snp_vlan_count; /*Global Vlan count*/
	BOOLEAN             g_pim_snoop_enabled;
	UINT32              pims_snp_vlan_count;
} MCGRP_GLOBAL_CLASS;

typedef struct MCAST_CLASS
{
    struct MCAST_CLASS  *inst_fwd;
    struct MCAST_CLASS  *inst_bwd;
    VRF_INDEX           vrf_index;

    UINT8               allocated;
    generic_pool_struct     *sptr_tx_free_entry_pool;
    generic_pool_struct *sptr_glb_mld_pool;
    generic_pool_struct *sptr_mldv2_sorted_list_pool;
    UINT16              source_virtual_port;
    UINT32              source_port;

    generic_pool_struct     *sptr_oif_info_pool;
    generic_pool_struct *sptr_vlan_info_pool;
    generic_pool_struct     *sptr_glb_grp_pool;
    generic_pool_struct     *sptr_source_pool; // Used for storing source data for IGMPv3 groups
    UINT32           ngroups;
    L2MCD_AVL_TREE      group_tree;

} MCAST_CLASS;


typedef struct MCAST_GLOBAL_CLASS
{
	MCAST_CLASS		*instances[IPVRF_MAX_VRF_IDX+1];
	MCAST_CLASS		*instances_list; /* List of actual configured multicast instances */
	MCAST_CLASS		*instances_list_end; /* pointer to the last element in the list */
} MCAST_GLOBAL_CLASS;

typedef struct s_MCGRP_CLIENT
{
	L2MCD_AVL_NODE       node;
	MADDR_ST          clnt_addr;

	//Wheel Timer Elem
	MCGRP_TIMER_ELEM  clnt_tmr;

} MCGRP_CLIENT;


#define MAX_PORT_NAME_LEN       32
typedef struct VE_ENTRY_
{
	UINT16			valid:1;
	UINT16			ve_enabled:1;
	UINT16			ve_type:6;     /* encode using enum VE_TYPE */
	UINT16			enable_mpls:1;
	UINT16			ipv4_rpf_mode:2;
	UINT16			ipv4_rpf_log:1;
	UINT16			ipv6_rpf_mode:2;
	UINT16			ipv6_rpf_log:1;
	UINT16			spare:1;
	VLAN_ID			vlan_id; 
	PORT_MASK		config_mask[MAX_SLOT];
	PORT_MASK		active_mask[MAX_SLOT];
	UINT32			last_change_timestamp;
	UINT8			name[MAX_PORT_NAME_LEN];
	PORT_MASK		vpls_ve_config_mask[MAX_SLOT]; /* contains only local ports */
} VE_ENTRY;

typedef struct VE_GLOBAL
{
	VE_ENTRY		*ve_table;
	UINT16			max_entries;
	UINT16			active_entries;
	PORT_MASK		ve_mask[MAX_SLOT];
	PORT_MASK		ve_mpls_mask[MAX_SLOT];
	UINT32			ve_debug;
} VE_GLOBAL;

extern VE_GLOBAL        ve_global;
#define g_ve_mask							ve_global.ve_mask
#define g_ve_table							ve_global.ve_table
#define g_ve_max_entries					ve_global.max_entries


#define MAX_PORT_PER_MODULE 64
#define MAX_MGMT_SLOT 2
#define MAX_PORT_PER_MGMT		1
#define MAX_SLAVE_SLOT 2 
#define MAX_PORT				((MAX_SLAVE_SLOT*MAX_PORT_PER_MODULE) + MAX_MGMT_PORT)
#define MAX_MGMT_PORT			(MAX_MGMT_SLOT*MAX_PORT_PER_MGMT)
#define FIRST_MGMT_SLOT		MAX_SLAVE_SLOT 	/* FIRST mgmt slot must come after last slave slot */
#define FIRST_MGMT_PORT		(MAX_SLAVE_SLOT*MAX_PORT_PER_MODULE)

#define MCGRP_MAX_ELAPSE_TIME               0xffffffff
#define MCGRP_PERIODIC_1_SECOND_TIMER       1


extern MCGRP_CLASS           mld;
extern MCGRP_CLASS           Mld0, *pMld0;
extern MCGRP_GLOBAL_CLASS    gMld, *pgMld;
extern MCGRP_CLASS           igmp;
extern MCGRP_CLASS           Igmp0, *pIgmp0;
extern MCGRP_GLOBAL_CLASS    gIgmp, *pgIgmp;

typedef struct IP_PARAMETERS
{
	ULONG 							source_address;
	ULONG 							destination_address;
	USHORT							offset;
	USHORT 							header_length;
	SERVICE_TYPE_BIT_STRUCTURE		type_of_service;
	USHORT							total_length;
	USHORT 							id;
	BYTE_ENUM (IP_PROTOCOL_VALUE)	protocol;
	BYTE_ENUM (BOOLEAN) 			do_not_fragment_flag;
	BYTE_ENUM (BOOLEAN) 			more_fragment_flag;
	BYTE 							time_to_live;
	BYTE 							options_length;
	BYTE							version;
	BYTE 							bIs_Hello_Pkt:1,
									spare:7;
	USHORT							checksum;
	UINT32							rx_port_number;
	UINT32							rx_phy_port_number;
	VLAN_ID							rx_vlan_id;
	ULONG 							gateway;
	VRF_INDEX						vrf_index;
	BYTE_ENUM (BOOLEAN) 			union_ip_packet_is_to_be_freed;
	void							*data;
} IP_PARAMETERS;

typedef UINT32 ITC_MSG_TYPE;
typedef UINT64 ITC_MSG_INSTANCE_ID;	/* Message instance id */
typedef struct
{
	ITC_MSG_TYPE msg_type;
	ITC_MSG_INSTANCE_ID msg_instance_id;
} ITC_MSG_HEADER;

typedef struct
{
	ITC_MSG_HEADER	header;
	IP_PARAMETERS	ip_param;
} IP_RX_PKT_MSG;


typedef struct IP6_PARAMETERS
{
	UINT8						hop_limit;
	UINT8						next_header;
	UINT32						traffic_class;
	UINT16						payload_length;
	IP6_IPV6_ADDRESS 			source_address;
	IP6_IPV6_ADDRESS 			destination_address;

	IPV6_INTERFACE_ID			rx_port_number;
    UINT32						rx_physical_port_number;
	UINT32						vrf_index;
	VLAN_ID						vlan_id;
} IP6_PARAMETERS;

typedef struct IP6_RX_PKT_MSG
{
	ITC_MSG_HEADER	header;
	IP6_PARAMETERS	ip_param;
	void				*pkt_data;
	UINT16			pkt_size;
} IP6_RX_PKT_MSG;

typedef	struct	IP_PORT_CONFIGURATION_CLASS
{
	UINT16 								port_number;
	USHORT 								mtu; 					/* IP level Maximum Transmission Unit, minimum of 28 bytes */
	UINT32                              ifindex;
	UINT32								vrf_index;
	UINT8								l2_encapsulation;
	BYTE_ENUM (BOOLEAN) 				port_enabled;
	BYTE_ENUM (BOOLEAN) 				admin_down;
	BYTE_ENUM (BOOLEAN)				arp_enabled;
	BYTE_ENUM (BOOLEAN)				bootp_enabled;
	BYTE_ENUM (BOOLEAN)				icmp_redirect_enabled;
	BYTE_ENUM (BOOLEAN)				local_proxy_arp_enabled;
	BYTE_ENUM (BOOLEAN)				ignore_gratuitous_arp_enabled;

	/*******************************************************/
	//Defnitions specific to router
	BYTE_ENUM (BOOLEAN) 				port_configured;
	BYTE_ENUM (BOOLEAN)				directed_bcast_fwd_enabled;
	USHORT								max_mtu;
	UINT32								cache_timeout;
	ULONG 								maximum_reassembly_size;
	UINT16								primary_port;
	UINT8								is_puppet;
	UINT8								acl_use_primary;
	UINT8								*route_map_name;
	void									*policy_route_map;
	void									*sptr_irdp;
	/*******************************************************/
	UINT8								dhcp_list_index;
	UINT8								next_gateway_to_use;
	UINT8								tunnel_mode;
	UINT16								mtu_configured;
	/*******************************************************/
	UINT16								donor_port; // applicable only for Donor/Unnumbered interafces
	UINT8								arp_suppression:1; // applicable only for Donor/Unnumbered interafces	
	UINT8								arp_suppression_cfg:1;
	UINT8								donor_port_cfg:1;
	UINT8								no_intf_op:1;
	UINT8								reserved:4;
} IP_PORT_CONFIGURATION_CLASS;


typedef	struct	IP_PORT_CLASS
{
	IP_PORT_CONFIGURATION_CLASS 		config;		
	BYTE_ENUM (BOOLEAN)				allow_broadcast;
	BYTE_ENUM (BOOLEAN)				port_is_up;
	UINT32								port_last_change_time_stamp; 	/* to store the snapshot of time at the operational status change */
} IP_PORT_CLASS;

typedef struct IP_ADDRESS_ENTRY
{
	struct IP_ADDRESS_ENTRY *sptr_forward_link;
	UINT32			mem_type;
	UINT32			ip_address;
	UINT32			ip_subnet_mask;
	UINT32			ip_subnet_address;
	UINT32			ip_subnet_broadcast_address;
	enum BOOLEAN	ip_address_dynamic;

	/*******************************************************/
	//Defnitions specific to router
	UINT32			disabled:1;			/* vrrp owner changed state to backup */
	UINT32			from_nvram:1;
	UINT32			ospf_type:2;
	UINT32			secondary_address:1; /* Additional router host address on same subnet */
    UINT32                  vip_address:1;          /* virtual ip address */
    UINT32                  spare:26;
	/*******************************************************/
} IP_ADDRESS_ENTRY;

typedef struct l3_listnode_
{
  struct l3_listnode_ *next;
  struct l3_listnode_ *prev;
  void *data;
} l3_listnode_t;

typedef struct IP_PORT_DB_ENTRY
{	
	struct IP_PORT_DB_ENTRY				*next;
	struct IP_PORT_DB_ENTRY				*prev;
	UINT16								port_number;// IP interface number
	UINT8								number_of_ip_addresses;	
	UINT8								number_of_ip_primary_addresses;	
	IP_PORT_CLASS						port; 
	IP_ADDRESS_ENTRY					*ip_address_table;					
	UINT32								icmp_meters;
	VRF_INDEX							vrf_index;
	UINT32								vrf_label;
	struct IP_PORT_DB_ENTRY				*donor_port;

    UINT8                               pim_enabled;
	l3_listnode_t                       list;
} IP_PORT_DB_ENTRY;


typedef struct IP_PORT_INFO
{
	IP_PORT_DB_ENTRY	**ip_port_db;
	IP_PORT_DB_ENTRY	*ip_port_db_list_head;
	IP_PORT_DB_ENTRY	*ip_port_db_list_tail;
	UINT32				number_active_ip_ports;

	IP_PORT_DB_ENTRY	*ip_port_db_pool;
	IP_ADDRESS_ENTRY	*ip_free_addr_entry;
	generic_pool_struct	*ip_addr_pool;
	UINT32 				init_addr_cnt;
	UINT32 				global_addr_cnt;

	UINT32				ip_addr_dy_pool_init;
  	generic_pool_struct 	ip_addr_dy_pool;

	char					*ip_port_sh_memory_reg;
	UINT32				ip_port_sh_mem_reg_size;
	
	UINT32				router_id[IPVRF_MAX_VRF_IDX+1];
	UINT32				config_router_id[IPVRF_MAX_VRF_IDX+1];
	UINT32				least_ip_address;


	UINT16				maximum_ip_ports;
	UINT32				spare:24;
	UINT32				max_addr_per_port:8;
	
	PORT_MASK			vport_member_mask[MAX_SLOT];
	MAC_ADDRESS		virtual_mac_addr;				// MAC address for all port members who are members of VE
	MAC_ADDRESS		config_virtual_mac_addr;		//Configured  MAC address for all port members who are members of VE
} IP_PORT_INFO;


#define IP_PORT_DB(port_number)				(gPortInfo.ip_port_db[(port_number) >= gPortInfo.maximum_ip_ports ? gPortInfo.maximum_ip_ports : port_number])
#define IP_IP_PORT(port_number)					(IP_PORT_DB(port_number)->port)

#define IP_PORT_DB_HEAD					(gPortInfo.ip_port_db_list_head)




extern IP_PORT_INFO gPortInfo;
extern IP6_IPV6_ADDRESS ip6_unspecified_address;
extern uint32_t mld_only_code;

typedef struct IP6_ADDRESS_ENTRY
{
	struct IP6_ADDRESS_ENTRY	*sptr_forward_link;
	struct IP6_ADDRESS_ENTRY	*sptr_subnet_addr;
	IP6_IPV6_ADDRESS			address;
	IP6_IPV6_ADDRESS			prefix;
	UINT8						prefix_length;
	UINT8						flags;
	UINT8						flags_reserved;
	UINT8						no_againg:4;
	UINT8						valid_memory:4;
    UINT32                      interface_id;

}IP6_ADDRESS_ENTRY;


#define IP6_MAXIMUM_LENGTH_OF_INTERFACE_IDENTIFIER		8
#define IP6_MAXIMUM_LINK_LAYER_ADDRESS_LENGTH			6
typedef	struct	IP6_PORT_CLASS {
	UINT8								type;
	UINT8								number_of_ip6_addresses;
	IPV6_INTERFACE_ID					interface_id;
	IP6_ADDRESS_ENTRY					*sptr_address_list;	//learned or configured non link local address
	IP6_ADDRESS_ENTRY					*sptr_ip6_link_local_address;
	UINT32								number_of_mcast_addr;
	UINT8								interface_identifier[IP6_MAXIMUM_LENGTH_OF_INTERFACE_IDENTIFIER];
	UINT8								interface_identifier_length;
	UINT8								link_layer_address_length;
	UINT8	 							link_layer_address[IP6_MAXIMUM_LINK_LAYER_ADDRESS_LENGTH]; 					/* in Big Endian format, ie. MSB is high order bit */
	UINT64								time_stamp;	//used for ecmp - LRU algorithm
	void								*sptr_pos_neighbor_entry;
} IP6_PORT_CLASS;

typedef struct IP6_PSEUDO_HEADER
{
	IP6_IPV6_ADDRESS 		source_address;
	IP6_IPV6_ADDRESS 		destination_address;
	UINT32						upper_layer_packet_length;
	UINT32						zero_field:24;
	UINT32 						next_header:8;
} IP6_PSEUDO_HEADER;


typedef struct IP6_UPPER_LAYER_PARAMETERS
{
	IP6_IPV6_ADDRESS 			source_address;
	IP6_IPV6_ADDRESS 			destination_address;
	IP6_IPV6_ADDRESS 			nexthop_address;
	enum BOOLEAN				hop_count_specified;
	UINT8						hop_count;		
	UINT8						protocol;	
	IPV6_INTERFACE_ID			tx_port_number;
	UINT32						extended_header_length;	//16920
	UINT8						traffic_class;
	UINT8						flags; // VRRP6
	UINT16 						phy_port; // this is used only if we want to send msg to a specific port 
										  // of a ve, the ve intf should be saved at the tx_port_number
	UINT32						vrf_index;
	void						*sptr_user_data; // VRRP6
	void					*ip_pkt_hello; /* SEND_HELLO_BY_PBIF */
} IP6_UPPER_LAYER_PARAMETERS;


typedef	struct 	IP6_CLASS
{

	UINT32 							number_of_ports;  
	IP6_PORT_CLASS					**sptr_port_database;
} IP6_CLASS;

typedef enum VE_TYPE
{
	VE_TYPE_NONE = 0,
	VE_TYPE_VLAN = 1,
	VE_TYPE_VPLS = 2
}VE_TYPE;


L2MCD_AVL_TREE *l3_portdb_tree;

GLOBAL IP6_CLASS ip6;
extern IP6_IPV6_ADDRESS ip6_unspecified_address;
GLOBAL IP6_IPV6_ADDRESS			ip6_link_local_all_nodes_address ;
GLOBAL IP6_IPV6_ADDRESS			ip6_link_local_all_routers_address;

#define GROUP_MEMBERSHIP_INTERVAL(mcgrp) \
    ((mcgrp->robustness_var * mcgrp->query_interval_time) + (mcgrp->max_response_time))

#define WILD_ADDRESS	0xE1 //use this address to crash system, prefer to use ASSERT or softcheck

#define IS_IP_PORT_DB_VALID(port_number)		(((port_number) != NO_SUCH_PORT) && (IP_PORT_DB(port_number) != (IP_PORT_DB_ENTRY *)WILD_ADDRESS))

#define IP6_PORT_IS_UP(x) (portdb_get_port_state(l3_portdb_tree, x))

#define	OTHER_QUERIER_PRESENT_INTERVAL(mcgrp) \
	((mcgrp->robustness_var * mcgrp->query_interval_time) + (mcgrp->max_response_time >> 1))

#define IP6_PORT_VRF_INDEX(_port_number_) (portdb_get_port_vrf_index(l3_portdb_tree, _port_number_))

#define FIRST_GRE_IP_TUNNEL_PORT	2048
#define LAST_GRE_IP_TUNNEL_PORT 10240
#define  is_ip_tnnl_port(port) 					(((port) >= FIRST_GRE_IP_TUNNEL_PORT) && ((port) <= LAST_GRE_IP_TUNNEL_PORT))

#define 	ROUTER_INT_TO_VID(rint)			((rint) - GET_MAX_PORT())

#define VELIB_IS_VALID_VID(vid) \
	((vid < g_ve_max_entries) ? (g_ve_table[vid].valid) : FALSE)

#define VELIB_GET_VID_TYPE(vid)	(g_ve_table[vid].ve_type)

#define IP6_MAX_L3_PORTS   l3_get_max_ports() 
#define MCGRP_IS_VALID_INTF(p)	            ((p) < MAX_MCGRP_INTFS)
#define IS_IP6_PORT_DB_VALID(x) ((x < IP6_MAX_L3_PORTS) && (portdb_is_port_index_valid(l3_portdb_tree, x)))
#define VELIB_GET_CONFIG_MASK(vid) \
	((vid < g_ve_max_entries) ? ((VE_TYPE_VLAN == VELIB_GET_VID_TYPE(vid)) ? (g_ve_table[vid].config_mask): \
	((VE_TYPE_VPLS == VELIB_GET_VID_TYPE(vid)) ? (g_ve_table[vid].vpls_ve_config_mask):NULL)) : NULL)

#define GRE_TNID_TO_ROUTER_INT(tnid) 	((tnid) + FIRST_GRE_IP_TUNNEL_PORT)
#define  is_valid_mcast_port(port) 			((port) < MAX_MC_INTFS)
#define IP_PORT_VRF_INDEX(port_number)              IP_PORT_DB(port_number)->vrf_index
#define MCGRP_AFI(mcgrp)                    ((mcgrp)->afi)
#define read_tb_sec() read_long_time_base()/G_1SEC_TB
#define read_tb_msec() read_long_time_base()/G_MSEC_TB
#define read_tb_sec() read_long_time_base()/G_1SEC_TB
#define MCGRP_CODE_2_VAL(x)     \
		( ((x) < 128) ? (x) : ( (((x) & 0x0F) | 0x10) << ( (((x) >> 4) & 0x07) + 3) ) )

#define MCGRP_VAL_2_CODE(x)     ( ((x) < 128) ? (x) : mcgrp_val2code(x) )

#define MCGRP_TIMER_GET_REMAINING_TIME(timerid, timer_elem) mcgrp_get_remaining_time((timerid), (timer_elem))

#define LAST_MGMT_SLOT		(FIRST_MGMT_SLOT+MAX_MGMT_SLOT-1)
#define IP_PORT_DB_NEXT(sptr_port_db)           (sptr_port_db = sptr_port_db->next)
#define MCGRP_IS_PORT_VIRTUAL(mcgrp_port)   ((mcgrp_port)->ve_port_mask != NULL)
#define IS_MGMT_SLOT(slot)		(((slot)>=FIRST_MGMT_SLOT)&&((slot)<=LAST_MGMT_SLOT))
#define MAKE_PORTID(module, module_port) 	(IS_MGMT_SLOT(module)? \
										(PORT_ID) ((FIRST_MGMT_PORT+(module))-FIRST_MGMT_SLOT): \
										(PORT_ID) (((module)<<2) | (module_port)))
#define MCGRP_IS_STATIC_MMBR(mcgrp, ver)  \
                              (((mcgrp)->afi == IP_IPV4_AFI) ? (((ver) & IGMP_STATIC_FLAG) > 0)\
                                      : (((ver) & MLD_STATIC_FLAG) > 0)) 

#define MCGRP_GET_VERSION(ver)           ((ver) & 0x3)


struct sockaddr_vlan
{
    /* Destination Mac address */
    unsigned char dest_mac[6];
    /* Source Mac address */
    unsigned char src_mac[6];
    /* Outgoing/Incoming interface index */
    unsigned int port;
    /* Vlan id */
    unsigned short vlanid;

}__attribute__((__packed__));
/* MLD IPv4 Socket Control Message Union */
union mld_in6_cmsg
{
  struct sockaddr sa;
  struct sockaddr_vlan vaddr;
};


typedef enum intf_type_new_s {
    INTF_MODE_UNK = 1,
    INTF_MODE_L2,
    INTF_MODE_L3,
    INTF_MODE_OF
} intf_type_new_t;

//MLD versions
#define MLD_VERSION_NONE							0
#define MLD_VERSION_1								1 
#define MLD_VERSION_2								2

//response time range
#define MLD_MIN_RESPONSE_TIME		1
#define MLD_MAX_RESPONSE_TIME		64
#define MLD_DFLT_RESPONSE_TIME		10

//query interval range
#define MLD_DFLT_QUERY_INTERVAL		125
#define MLD_MIN_QUERY_INTERVAL		1
#define MLD_MAX_QUERY_INTERVAL		3600

//last listener query interval range in seconds
#define MLD_DFLT_LLQI	1
#define MLD_MIN_LLQI  	1
#define MLD_MAX_LLQI 	25

//robustness variable range
#define MLD_DFLT_ROBUSTNESS	2
#define MLD_MIN_ROBUSTNESS	2
#define MLD_MAX_ROBUSTNESS	7

#define MLD_DFLT_PRUNE_WAIT_TIME    3

//response time range
#define MLD_MIN_RESPONSE_TIME		1
#define MLD_MAX_RESPONSE_TIME		64
#define MLD_DFLT_RESPONSE_TIME		10

//msg types
#define MLD_MEMBERSHIP_QUERY_TYPE					130
#define MLD_V1_MEMBERSHIP_REPORT_TYPE				131
#define MLD_V2_MEMBERSHIP_REPORT_TYPE				143
#define MLD_V1_LEAVE_GROUP_TYPE						132


extern unsigned long long l3_ref_time;
/**************************************************
 * Function Prototypes
 **************************************************/

BOOLEAN mcgrp_global_pools_init (UINT32  afi);
void mcgrp_service_wheel_timer_ms (UINT32 afi);
TRUNK_STATE trunk_port_state(PORT_ID port);
void mcgrp_service_wheel_timer (UINT32 afi);
int mcgrp_addr_cmp_cb_param (const void *keya, const void *keyb, void *param);
void set_mask_bit(PORT_MASK *mask, int port);
void clear_mask_bit(PORT_MASK *mask, int port);
void mcgrp_free_source (MCGRP_CLASS   *mcgrp, MCGRP_SOURCE  *mcgrp_src);
void mcgrp_free_client (MCGRP_CLASS   *mcgrp, MCGRP_CLIENT  *mcgrp_clnt);
TRUNK_ID trunk_id_get(PORT_ID port );
UINT32 mcgrp_get_remaining_time(WheelTimerId timer_id, WheelTimerElement *timer_elem);
USHORT calculate_ip_checksum (PSEUDO_IP_PARAMETERS *sptr_pseudo_header, BYTE *bptr_start_from, USHORT length);
BOOLEAN is_trunk_up( TRUNK_ID trunk_id );

unsigned long sys_get_timeticks();
unsigned long long sys_get_millisecond(void);

void l2mcd_sync_pims_upd_inherit_ports_to_sg(MCGRP_ENTRY *mcgrp_entry, 
										MCGRP_MBRSHP *rcvd_mbrshp,
										uint32_t vid, uint32_t phy_ifindex, 
										UINT8 afi, UINT8 add,UINT32 ivid);
BOOLEAN pim_snoop_is_source_present_on_mbr_port(MCGRP_MBRSHP *grp_mbrshp, 
						uint32_t src_addr, uint8_t afi);
void l2mcd_sync_inherit_and_send_rte(MCGRP_CLASS  *mcgrp, MCGRP_L3IF *mcgrp_vport, 
									   MCGRP_ENTRY *mcgrp_entry, UINT32 phy_port_id, MADDR_ST *src_addr, int add_flag);

BOOLEAN pims_is_pim_snoop_mbrship(MCGRP_MBRSHP *mcgrp_mbrshp);
void mcgrp_pims_age_src_mbrshp(MCGRP_CLASS  *mcgrp, MCGRP_L3IF *mcgrp_vport,
						MCGRP_ENTRY *mcgrp_entry, MCGRP_MBRSHP *mcgrp_mbrshp,
						MCGRP_SOURCE *pims_src_entry);

MCGRP_SOURCE* mcgrp_pims_find_src_node_by_addr (MCGRP_CLASS  *mcgrp,
											MCGRP_MBRSHP *mcgrp_mbrshp,
											MADDR_ST *src_addr);

void mcgrp_pims_sorted_linklist_del_element(MCGRP_GLOBAL_CLASS *mcgrp_glb,
								MCGRP_CLASS  *mcgrp, MCGRP_MBRSHP *mcgrp_mbrshp,
								MADDR_ST *src_addr);

int mcgrp_addr_cmp_cb(void *keya, void *keyb);
int mcgrp_addr_cmp_cb_param(const void *keya, const void *keyb, void *param);
int mcgrp_port_id_cmp_cb(void *keya, void *keyb);
int mcgrp_port_id_cmp_cb_param(void *keya, void *keyb, void *param);
void mcgrp_process_wte_event(void *wte_param);
int receive_igmp_packet (IP_PARAMETERS  *sptr_ip_parameters);
MCGRP_MBRSHP* mcgrp_find_mbrshp_entry_for_grpaddr (MCGRP_CLASS  *mcgrp, 
        MADDR_ST     *group_address, 
        UINT16        vir_port_id, 
        UINT32        phy_port_id);
void mcgrp_notify_vif_add (MCGRP_CLASS   *mcgrp,
        MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport,
        MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_ENTRY   *mcgrp_entry,
        BOOL           sigchange);
void mcgrp_notify_vif_del(MCGRP_CLASS  *mcgrp, 
        MADDR_ST     *group_address,
        MCGRP_L3IF   *mcgrp_vport,
        MCGRP_ENTRY   *mcgrp_entry,
        BOOL          sigchange);                                                  
MCGRP_CLASS  *mcgrp_vrf_alloc (UINT32 afi, VRF_INDEX  vrf_index);
MCGRP_L3IF* mcgrp_create_l3intf (MCGRP_CLASS  *mcgrp, UINT16        vir_port_id);
MCGRP_MBRSHP* mcgrp_find_first_mbrshp (MCGRP_ENTRY *mcgrp_grp);
MCGRP_MBRSHP* mcgrp_find_next_mbrshp (MCGRP_ENTRY   *mcgrp_grp,
        MCGRP_MBRSHP  *mcgrp_mbrshp);
MCGRP_ENTRY* mcgrp_find_group_address_entry (MCGRP_CLASS  *mcgrp, 
        UINT16        vir_port_id, MADDR_ST     *group_address);
MCGRP_SOURCE* mcgrp_find_source (MCGRP_MBRSHP      *mcgrp_mbrshp, 
        MADDR_ST          *src_addr, MCGRP_FILTER_MODE  src_mode);
MCGRP_L3IF *mcgrp_alloc_init_l3if_entry (MCGRP_CLASS   *mcgrp, UINT16         vir_port_id);
MCGRP_ENTRY* mcgrp_alloc_group_entry (MCGRP_CLASS  *mcgrp,
        MCGRP_L3IF   *mcgrp_l3if, MADDR_ST     *group_address);
MCGRP_MBRSHP* mcgrp_alloc_add_mbrshp_entry (MCGRP_CLASS  *mcgrp, 
        MCGRP_ENTRY  *grp_entry, MCGRP_L3IF   *mcgrp_vport, 
        UINT32        phy_port_id, BOOLEAN       is_static, 
        UINT8         version);
GROUP_ENTRY* mld_mcgrp_find_insert_glb_group_entry (MCGRP_CLASS  *mcgrp, 
                                                MADDR_ST     *grp_address);
MCGRP_MBRSHP* mcgrp_find_mbrshp_entry (MCGRP_ENTRY  *grp_entry, UINT32 phy_port_id);
BOOLEAN igmp_send_igmp_message (MCGRP_CLASS *igmp, UINT16 tx_port_number,
        UINT32 physical_port, UINT8 type, UINT8 version,
        UINT32 group_address,  UINT32 source_address,
        UINT16 response_time, MCGRP_SOURCE*   src_list, BOOLEAN all_srcs,
        BOOLEAN is_retx);
void mcgrp_notify_phy_port_del (MCGRP_CLASS *mcgrp, MADDR_ST *group_address,
        MCGRP_L3IF *mcgrp_vport, UINT32 phy_port_id, BOOL sigchange);
void mcgrp_destroy_mbrshp_entry (MCGRP_CLASS  *mcgrp, MCGRP_ENTRY  *grp_entry, 
        MCGRP_MBRSHP *mcgrp_mbrshp);
void mcgrp_destroy_group_addr (MCGRP_CLASS  *mcgrp, MCGRP_L3IF   *vport, 
        MCGRP_ENTRY  *del_group);
int l3_get_port_from_ifindex(int ifindex);
int igmp_set_if_igmp_version (VRF_INDEX vrf_index, UINT16 vport, UINT8 version);
MCGRP_PORT_ENTRY* mcgrp_add_phy_port (MCGRP_CLASS  *mcgrp, MCGRP_L3IF   *mcgrp_vport,
        UINT32        phy_port_id);
void mcgrp_vport_state_notify (MCGRP_CLASS  *mcgrp, UINT16        vir_port_id,
        UINT32        phy_port_id, BOOLEAN       up);
void mcgrp_delete_veport (MCGRP_CLASS *mcgrp, MCGRP_L3IF *mcgrp_vport, UINT32 phy_port_id);
void igmp_send_general_query( MCGRP_CLASS *igmp, UINT16       tx_port_number,
        UINT32       physical_port, UINT8        version, UINT32       use_src,
        UINT16       response_time);
MCGRP_PORT_ENTRY* mcgrp_find_phy_port_entry (MCGRP_CLASS  *mcgrp, MCGRP_L3IF   *mcgrp_vport,
        UINT32        phy_port_id);
void mld_tx_static_report_leave_on_mrtr_port(MCGRP_CLASS  *mld, MADDR_ST *grp_addr, MCGRP_L3IF *mld_vport, 
											 uint32_t rx_phy_port, uint8_t joinflag);
UINT32 ip_get_lowest_ip_address_on_port(UINT16 port_number, uint8_t type);
BOOLEAN igmp_update_ssm_parameters(MCGRP_CLASS *mcgrp, MADDR_ST *group_addr, UINT8 *version,
        PORT_ID vir_port_id, UINT32 phy_port_id, UINT8 *igmp_action, UINT16 *num_srcs,
        UINT32 **src_list);
MCGRP_MBRSHP* mcgrp_update_group_address_table (MCGRP_CLASS *mcgrp, UINT16 vir_port_id, 
        UINT32 phy_port_id, MADDR_ST *group_address, MADDR_ST *clnt_src_ip, 
        UINT8 action, UINT8 version, UINT16 num_srcs, void *src_array);
int l2mcd_system_group_entry_notify(MADDR_ST *group_address, MADDR_ST *src_address, int vir_port,int phy_port_id, int is_static, int insert);
int l2mcd_system_mrouter_notify(int vir_port, int phy_port_id, int is_static, int insert);
void mcgrp_port_state_notify (UINT32 afi, VRF_INDEX vrf_index, UINT16 port_id, enum BOOLEAN  up);
void mcgrp_delete_l3intf (MCGRP_CLASS  *mcgrp, UINT16        vir_port_id);
enum BOOLEAN igmp_check_valid_range(UINT32  group_address);
unsigned short l3_get_port_from_bd_id(unsigned int bd_id);
void igmp_reset_default_values(MCGRP_CLASS *igmp);
void mld_vport_state_notify (UINT16   vir_port_id, UINT32   phy_port_id, BOOLEAN  up, MCGRP_CLASS *mld);
enum BOOLEAN is_physical_or_lag_port(int port);
void mcgrp_notify_source_del_allowed (MCGRP_CLASS *mcgrp, MADDR_ST *group_address,
        MCGRP_L3IF *mcgrp_vport, MCGRP_MBRSHP *mcgrp_mbrshp, MADDR_ST *source_addr,
        BOOL sigchange);
void mcgrp_notify_source_add_blocked (MCGRP_CLASS   *mcgrp, MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport, MCGRP_MBRSHP  *mcgrp_mbrshp, MADDR_ST      *src_addr,
        BOOL           sigchange);
void mcgrp_update_age_for_clnts (MCGRP_CLASS  *mcgrp, L2MCD_AVL_TREE  *clnt_tree, 
        MADDR_ST     *clnt_ip_addr, UINT16        time);
BOOLEAN igmpv3_send_group_source_query(MCGRP_CLASS *igmp, MCGRP_MBRSHP *igmp_mbrshp,
        UINT16 vir_port_id, UINT32 phy_port_id, UINT32 group_address,
        SORTED_LINKLIST** p_src_list, BOOLEAN was_excl, UINT32 clnt_ip_addr, BOOLEAN is_retx);
BOOLEAN igmp_send_group_query(MCGRP_CLASS *igmp, MCGRP_MBRSHP* igmp_mbrshp, UINT16 tx_port_number,
        UINT32 physical_port, UINT8 version, UINT32 group_address, UINT32 src_ip, UINT32 clnt_ip_addr,
        BOOLEAN is_retx);
void mcgrp_transition_to_INCL (MCGRP_CLASS   *mcgrp, MCGRP_L3IF    *mcgrp_vport, MCGRP_MBRSHP  *mcgrp_mbrshp,
        MCGRP_ENTRY   *mcgrp_entry);
void mcgrp_destroy_tracking_list (MCGRP_CLASS  *mcgrp, L2MCD_AVL_TREE  *clnt_tree);
void mld_dump_mbrshp (MCGRP_CLASS   *mld, MCGRP_MBRSHP  *mld_mbrshp);
void igmp_set_global_version (VRF_INDEX vrf_index, UINT32 version, BOOL force);
BOOL mcgrp_initialize (UINT32 afi, MCGRP_CLASS *mcgrp);
void mcgrp_handle_intf_ver_change (MCGRP_CLASS  *mcgrp, MCGRP_L3IF   *mcgrp_vport);
void mcgrp_stop_tracking (MCGRP_CLASS  *mcgrp, MCGRP_L3IF   *mcgrp_vport);
BOOLEAN pim_enabled (UINT32 afi, UINT16 port);
void mcgrp_stop_phy_port (MCGRP_CLASS *mcgrp, MCGRP_L3IF *mcgrp_vport, MCGRP_PORT_ENTRY *mcgrp_pport);
void mcgrp_start_phy_port (MCGRP_CLASS *mcgrp, MCGRP_L3IF *mcgrp_vport, MCGRP_PORT_ENTRY *mcgrp_pport);
void mcgrp_stop_vir_port (MCGRP_CLASS  *mcgrp, MCGRP_L3IF   *mcgrp_vport);
void mcgrp_start_vir_port (MCGRP_CLASS *mcgrp, MCGRP_L3IF *mcgrp_vport);
void mcgrp_mcast_change_vport_membership (MCGRP_CLASS *mcgrp, MADDR_ST *source_address,
        MADDR_ST *group_address, UINT16 router_port, UINT32 phy_port, UINT32 mcgrp_op);
void igmpv3_sorted_linklist_free_list (MCGRP_CLASS *igmp, generic_pool_struct *pool, 
        SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST *src);
void mldv2_sorted_linklist_free_list (MCGRP_CLASS *mld, generic_pool_struct *pool,
        SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST *src);
void mcgrp_mcast_change_vport_membership (MCGRP_CLASS  *mcgrp, MADDR_ST *source_address,
        MADDR_ST *group_address, UINT16 router_port, UINT32 phy_port, UINT32 mcgrp_op);
void mcgrp_add_update_client (MCGRP_CLASS *mcgrp, L2MCD_AVL_TREE *clnt_tree, MADDR_ST *clnt_addr);
BOOL mcgrp_src_list_empty ( MCGRP_MBRSHP *mcgrp_mbrsh, MCGRP_FILTER_MODE src_mode, UINT8 version);
BOOLEAN mcgrp_send_group_source_query (MCGRP_CLASS *mcgrp, MCGRP_MBRSHP *mcgrp_mbrshp,
        UINT16 vir_port_id, UINT32 phy_port_id, MADDR_ST *group_address, SORTED_LINKLIST **p_src_list,
        BOOLEAN was_excl, MADDR_ST *clnt_ip_addr, enum BOOLEAN is_retx);
void igmpv3_sorted_linklist_keep_common (MCGRP_CLASS *igmp, generic_pool_struct *pool,
        SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
void mldv2_sorted_linklist_keep_common (MCGRP_CLASS *mld, generic_pool_struct *pool,
        SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
void igmpv3_sorted_linklist_minus (MCGRP_CLASS *igmp, generic_pool_struct *pool,
        SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
void mldv2_sorted_linklist_minus (MCGRP_CLASS *mld, generic_pool_struct *pool,
        SORTED_LINKLIST_KEYINFO *key_info, SORTED_LINKLIST **dest_p, SORTED_LINKLIST *src);
MCGRP_SOURCE* mcgrp_delist_source (MCGRP_MBRSHP *mcgrp_mbrshp, MADDR_ST *src_addr, MCGRP_FILTER_MODE src_mode);
BOOLEAN igmp_staticGroup_exists_on_port (IP_ADDRESS  group_addr, PORT_ID port_id, UINT32 phy_port);
BOOLEAN mld_staticGroup_exists_on_port (IPV6_ADDRESS *group_addr, PORT_ID port_id, UINT32 phy_port);
int igmpv3_encode_src_list (IGMPV3_MESSAGE *igmpv3_msg, MCGRP_SOURCE *p_src, BOOLEAN all_srcs, BOOLEAN is_retx);
int l2mcd_send_pkt(void *itc_msg, ifindex_t phy_port_id, uint16_t vlan_id ,  MADDR_ST *grp_addr, MCGRP_CLASS  *mld, MCGRP_GLOBAL_CLASS  *mcgrp_glb, 
    bool_t is_forwarded, bool_t is_bcast);
void mld_tx_reports_leave_rcvd_on_edge_port(void *req, MADDR_ST *grp_addr, MCGRP_CLASS  *mld, MCGRP_L3IF *mld_vport);
void igmpv3_destroy_client (MCGRP_CLASS *mcgrp, L2MCD_AVL_TREE *clnt_tree, UINT32 clnt_addr);
void mcgrp_notify_source_list_add_blocked (MCGRP_CLASS   *mcgrp, MADDR_ST      *group_address,
        MCGRP_L3IF    *mcgrp_vport, MCGRP_MBRSHP  *mcgrp_mbrshp, MCGRP_SOURCE  *src_list,
        BOOL           sigchange);
void mcgrp_start_query_process (MCGRP_CLASS *mcgrp, MCGRP_PORT_ENTRY *mcgrp_pport, 
        UINT16 vir_port_id, UINT32 phy_port_id);
void mcgrp_activate_static_groups (MCGRP_CLASS  *mcgrp, UINT16 vir_port_id, UINT32 target_port);

void mld_send_l2mcd_sync_group_upd (MADDR_ST *group_address,  
        UINT16 vir_port_id, int num_add_port, UINT32 add_phy_port_id, 
        int num_del_port, UINT32 del_phy_port_id, MADDR_ST  *src_addr, 
        uint8_t is_remote_report);
void mld_send_l2mcd_sync_group_clr (UINT16 ivid, BOOLEAN isGlobalClear, uint8_t afi);
void mld_send_l2mcd_sync_group_add (MADDR_ST *group_address, 
        UINT16 vir_port_id, UINT32 phy_port_id, MADDR_ST  *src_addr, UINT8  filter_mode) ;
void igmpv3_send_l2mcd_sync_group_upd (MADDR_ST *group_address, 
        UINT16 vir_port_id, int num_add_port, UINT32 add_phy_port_id, 
        int num_del_port, UINT32 del_phy_port_id, MADDR_ST  *src_addr, 
        uint8_t is_remote_report, UINT8  filter_mode);

void igmpv3_send_l2mcd_sync_group_add (MADDR_ST *group_address, 
        UINT16 vir_port_id, UINT32 phy_port_id, MADDR_ST  *src_addr, UINT8  filter_mode);

void l2mcd_sync_inherit_xg_port_to_all_sg (MCGRP_ENTRY *mcgrp_entry, uint32_t phy_ifindex, uint32_t vid, int add);

void l2mcd_sync_inherit_xg_ports_to_this_sg (MCGRP_ENTRY *mcgrp_entry, MADDR_ST *src_addr, UINT8 filter_mode, uint32_t vid, int add);
#endif
