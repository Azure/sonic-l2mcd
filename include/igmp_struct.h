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

#ifndef _IGMP_STRUCT_
#define _IGMP_STRUCT_

#include "l2mcd_data_struct.h"


typedef struct VERSION_LENGTH_BIT_STRUCTURE
{
#if __BYTE_ORDER  != __BIG_ENDIAN
	unsigned char		header_length:4;
	unsigned char		version:4;
#else
	unsigned char		version:4;
	unsigned char		header_length:4;
#endif
} VERSION_LENGTH_BIT_STRUCTURE;

typedef struct SERVICE_TYPE_BIT_STRUCTURE
{
#if __BYTE_ORDER  != __BIG_ENDIAN
	unsigned char 		unused:2;
	unsigned char 		high_reliability:1;
	unsigned char 		high_throughput:1;
	unsigned char 		low_delay:1;
	unsigned char 		precedence:3;
#else
	unsigned char 		precedence:3;
	unsigned char 		low_delay:1;
	unsigned char 		high_throughput:1;
	unsigned char		high_reliability:1;
	unsigned char		unused:2;
#endif
} SERVICE_TYPE_BIT_STRUCTURE;

typedef struct FLAG_FRAGMENT_OFFSET_BIT_STRUCTURE
{
#if __BYTE_ORDER  != __BIG_ENDIAN
	unsigned char		fragment_offset_most_significant_part:5;
	unsigned char		more_fragment_flag:1;
	unsigned char		do_not_fragment_flag:1;
	unsigned char		unused_bit:1;
#else
	unsigned char		unused_bit:1;
	unsigned char		do_not_fragment_flag:1;
	unsigned char		more_fragment_flag:1;
	unsigned char		fragment_offset_most_significant_part:5;
#endif
} FLAG_FRAGMENT_OFFSET_BIT_STRUCTURE;


typedef struct IP_HEADER
{

	VERSION_LENGTH_BIT_STRUCTURE 					version_header_length;
	SERVICE_TYPE_BIT_STRUCTURE						service_type;
	USHORT											total_length;
	USHORT											identifier;	
	FLAG_FRAGMENT_OFFSET_BIT_STRUCTURE 				flags_fragment_offset;
	BYTE											fragment_offset_least_significant_part;
	BYTE											time_to_live;
	BYTE											protocol;
	USHORT											header_checksum;
	UINT32											source_ip_address;
	UINT32											destination_ip_address;
} IP_HEADER;

typedef struct IP_OPTION_HEADER
{
#if __BYTE_ORDER == __BIG_ENDIAN
	UINT8		copy_option_on_fragmentation:1;
	UINT8		option_class:2;
	UINT8		option_number:5;	
#else
	UINT8		option_number:5;
	UINT8		option_class:2;
	UINT8		copy_option_on_fragmentation:1;
#endif /* BIG_ENDIAN */
} IP_OPTION_HEADER;


typedef struct IP_ROUTER_ALERT_OPTION_BODY
{
	IP_OPTION_HEADER 			code;
	UINT8						length;
	UINT16						value;
} IP_ROUTER_ALERT_OPTION_BODY;


#define IGMPV3_GROUP_REC_HDR_SIZE 8

enum IGMP_VERSION
{
	IGMP_VERSION_NONE     = 0,
	IGMP_VERSION_1	      = 1,
	IGMP_VERSION_2	      = 2,
	IGMP_VERSION_3	      = 3,
	NUM_IGMP_VERSION      = 3,
	IGMP_REMOTE_FLAG      = 0x40,
	IGMP_STATIC_FLAG      = 0x80,
	IGMP_STATIC_VER1      = IGMP_STATIC_FLAG | IGMP_VERSION_1,
	IGMP_STATIC_VER2      = IGMP_STATIC_FLAG | IGMP_VERSION_2,
	IGMP_STATIC_VER3      = IGMP_STATIC_FLAG | IGMP_VERSION_3,
	IGMP_VERSION_DEFAULT  = IGMP_VERSION_2
};

#define IGMP_IS_STATIC_MMBR(ver)        (((ver) & IGMP_STATIC_FLAG) > 0)
#define IGMP_IS_REMOTE_MMBR(ver)        (((ver) & IGMP_REMOTE_FLAG) > 0)
#define IGMP_GET_VERSION(ver)           ((ver) & 0x3)
#define MCGRP_MAX_ACTION_TYPE              6
//robustness variable range
#define IGMP_DFLT_ROBUSTNESS	2
#define IGMP_MIN_ROBUSTNESS	2
#define IGMP_MAX_ROBUSTNESS	7
#define IGMP_DFLT_LLQI	1
#define IGMP_MIN_LLQI  	1
#define IGMP_MAX_LLQI 	10
#define INITIAL_VLAN_LIST_ENTRY_NUM 2000
#define INITIAL_TX_PORT_INFO_NUM 1024



// IGMP v1/v2 Query Message
typedef struct IGMP_MESSAGE
{
	UINT8	type;
	UINT8	maximum_response_time;
	UINT16	checksum;
	UINT32	group_address;

} IGMP_MESSAGE;


// IGMPV3 Query Message
typedef struct IGMPV3_MESSAGE
{	// Note, the first 4 fields must be the same as IGMP_MESSAGE
	UINT8	type;
	UINT8	maximum_response_code;
	UINT16	checksum;
	UINT32	group_address;

// The following are the IGMPV3 extensions
	UINT8	reserved                : 4;
	UINT8	suppress_router_process : 1;
	UINT8	robustness_var          : 3;       // querier's robustness variable

	UINT8	query_interval_code;               // querier's interval code
	UINT16	num_srcs;
	UINT32	source_ary[1];         // num_srcs number

} IGMPV3_MESSAGE;

typedef struct IGMPV3_GROUP_RECORD
{
	UINT8 type;
	UINT8 aux_data_len;
	UINT16 num_srcs;
	UINT32 group_address;
	UINT32 source_address_ary[1]; // num_of_sources.

} IGMPV3_GROUP_RECORD;

typedef struct IGMPV3_REPORT
{
	UINT8	type;
	UINT8	reserved_uint8;
	UINT16	checksum;
	UINT16	reserved_uint16;
	UINT16	num_grps;
	IGMPV3_GROUP_RECORD group_record[1]; 	// num_grps number 

} IGMPV3_REPORT;

typedef struct IGMP_PACKET
{
	IP_HEADER					ip_header;
	IP_ROUTER_ALERT_OPTION_BODY	ip_options;
	IGMP_MESSAGE				igmp_message;
} IGMP_PACKET;

typedef struct IGMPV3_PACKET
{
	IP_HEADER					ip_header;
	IP_ROUTER_ALERT_OPTION_BODY	ip_options;
	IGMPV3_MESSAGE				igmp_message;	
}IGMPV3_PACKET;

typedef struct IGMPV3_GROUP_PACKET
{
    IP_HEADER                   ip_header;
    IP_ROUTER_ALERT_OPTION_BODY ip_options;
	IGMPV3_REPORT               igmp_report; 
}IGMPV3_GROUP_PACKET;

#define PIM_QUERY 0
#define	PIM_V1 1
#define	PIM_V2 2

typedef struct PIM_V2_HDR
{
	uint8_t   type:4;		
	uint8_t   pim_version:4;	
	uint8_t   reserved:4;
	uint8_t   subtype:4;
    uint16_t  checksum;
} PIM_V2_HDR;

typedef struct PIM_HELLO_MSG {
  UINT16	option_type;      /* 1, Hold time */
  UINT16	option_length;    /* 2, next field is holdtime value */
  UINT32	holdtime;	
} PIM_HELLO_MSG;


extern SORTED_LINKLIST_KEYINFO igmpv3_src_keyinfo;


// Given the max-response-time and IGMP pkt size, this macro
// determines the version of the Query
// The macro returns the result in the first argument that is passed in
//
// NOTE that this macro does not check if the msg is a query msg
// This is left up to the caller to determine
#define IGMP_EVAL_QUERY_VERSION(res, max_resp_time, igmp_msg_sz)    \
{                                                                   \
	if (max_resp_time == 0)                                         \
		res = IGMP_VERSION_1;                                       \
	else if (igmp_msg_sz == 8)                                      \
		res = IGMP_VERSION_2;                                       \
	else if (igmp_msg_sz >= 12)                                     \
		res = IGMP_VERSION_3;                                       \
	else                                                            \
		res = IGMP_VERSION_NONE;                                    \
}

#define NEXT_GRP_REC(grp_rec)  (IGMPV3_GROUP_RECORD*)                                          \
								( (unsigned long) (grp_rec)->source_address_ary                         \
									+ ((net_to_host_short( \
									((grp_rec)->num_srcs)) \
									+ net_to_host_short((grp_rec)->aux_data_len)) << 2) );											  	  


typedef struct IGMP_STATS
{
	// Query - receive
	UINT32	igmp_recv_gen_query_msg[3];    // general query
	UINT32	igmp_recv_grp_query_msg;       // group specific query
	UINT32	igmp_recv_grp_src_query_msg;   // group/source specific query
	UINT32  igmp_wrong_ver_query;

	// Query - transmit
	UINT32	igmp_xmt_gen_query_msg[3];     // general query
	UINT32	igmp_xmt_grp_query_msg;        // group specific query
	UINT32	igmp_xmt_grp_src_query_msg;    // group/source specific query

	// Reports
	UINT32	igmp_recv_membership_ary[3];   // Reports

	// Reports, broken down into report-types
	UINT32	igmpv3_msg_type[MCGRP_MAX_ACTION_TYPE];   // IS_IN, IS_EX, TO_IN, TO_EX, ALLOW, BLOCK

	// Leaves
	UINT32	igmp_recv_leave_msg;

	// Miscellaneous error stats
	UINT32	recv_checksum_error;
	UINT32	recv_size_or_range_error;

	//SSM Mapping Error
	UINT32 	igmp_ssm_map_error;

	UINT32	recv_packets;
	UINT32	xmt_packets;
	UINT32  xmt_error;

    UINT32 isl_membership_query_rcvd;
    UINT32 isl_v1_membership_report_rcvd;
    UINT32 isl_v2_membership_report_rcvd;
    UINT32 isl_v2_group_leave_rcvd;
    UINT32 pim_hello_pkt_rcvd;

} IGMP_STATS;

typedef struct MLD_STATS
{

	UINT32  mld_wrong_ver_query;
	// Miscellaneous error stats
	UINT32	recv_checksum_error;
	UINT32	recv_size_or_range_error;

	UINT32	recv_packets;
	UINT32	xmt_packets;
	UINT32 pim_hello_pkt_rcvd;
} MLD_STATS;

extern SORTED_LINKLIST_KEYINFO mldv2_src_keyinfo;
extern SORTED_LINKLIST_KEYINFO mldv2_clnt_keyinfo;

enum MLD_VERSION
{
	MLD_NONE             = 0,
	MLD_VER_1	         = 1,
	MLD_VER_2	         = 2,
	NUM_MLD_VERSION      = 2,
	MLD_STATIC_FLAG      = 0x80,
	MLD_STATIC_VER1      = MLD_STATIC_FLAG | MLD_VER_1,
	MLD_STATIC_VER2      = MLD_STATIC_FLAG | MLD_VER_2,
	MLD_VERSION_DEFAULT  = MLD_VER_1

};
void igmp_enable (VRF_INDEX  vrf_index, UINT8      protocol);
BOOLEAN mcgrp_initialize_port_db_array(UINT32 afi);
#endif /*IGMP_STRUCT*/

