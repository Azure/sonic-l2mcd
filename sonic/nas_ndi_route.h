
/*
 * Copyright (c) 2016 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * THIS CODE IS PROVIDED ON AN  *AS IS* BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
 *  LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
 * FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 * See the Apache Version 2.0 License for specific language governing
 * permissions and limitations under the License.
 */


/*
 * filename: nas_ndi_route.h
 */


#ifndef __NAS_NDI_ROUTE_H
#define __NAS_NDI_ROUTE_H

#include "std_error_codes.h"
#include "ds_common_types.h"
#include "nas_ndi_common.h"
#include "nas_ndi_router_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup NDI API - Route/L3 Functionality
 *
 *  \{
 */

#define NDI_MAX_ROUTE_ATTR    5
#define NDI_MAX_NEXT_HOP_ATTR 4
#define NDI_MAX_NEIGHBOR_ATTR 3
#define NDI_MAX_GROUP_NEXT_HOP_ATTR 3

/*
 * Next_hop Id type
 */
typedef ndi_obj_id_t next_hop_id_t;

/*
 * Attribute flags for route or host info
 *
 * Contains different types attribute flags
 *
 */
typedef enum {
    NDI_ROUTE_L3_DEFAULT        = (1 << 0),  /* L3 terminated */
    NDI_ROUTE_L3_TERMINATED     = (1 << 1),  /* L3 terminated */
    NDI_ROUTE_L3_ECMP           = (1 << 2),  /* ECMP Route*/
    NDI_ROUTE_L3_PACKET_ACTION  = (1 << 3),
    NDI_ROUTE_L3_TRAP_PRIORITY  = (1 << 4),
    NDI_ROUTE_L3_NEXT_HOP_ID    = (1 << 5),
    NDI_ROUTE_L3_INVALID        = (1 << 31)
} ndi_route_flags;

/*
 * Attribute data for route packet action
 *
 * Contains different types of route packet action for NPUs
 *
 */
typedef enum {
    NDI_ROUTE_PACKET_ACTION_DROP,        /* Drop packet */
    NDI_ROUTE_PACKET_ACTION_TRAPCPU,     /* Trap Packet to CPU */
    NDI_ROUTE_PACKET_ACTION_FORWARD,     /* Forward Packet */
    NDI_ROUTE_PACKET_ACTION_TRAPFORWARD, /* Trap and Forward the packet */
    NDI_ROUTE_PACKET_ACTION_INVALID
} ndi_route_packet_action_type;

typedef ndi_route_packet_action_type ndi_route_action;

/*
 * @brief the route data structure
 *
 * Forwarding database L3 Route Structure
 *
 * Contains data on L3 route table entries in SAI.
 */

typedef struct ndi_route_s {
    npu_id_t                npu_id;       /* NPU ID. */
    ndi_route_flags         flags;        /* Route flags */
    ndi_route_action        action;
    ndi_vrf_id_t            vrf_id;       /* VRF Id . */
    hal_ip_addr_t           prefix;       /* Prefix address */
    uint32_t                mask_len;     /* IPv4/ipv6 subnet mask length*/
    hal_ip_addr_t           nexthop;      /* Next hop IPv4 address  */
    next_hop_id_t           nh_handle;    /* Next hop handle */
    ndi_rif_id_t            rif_id;       /* Router Interface Id */
    int                     priority;     /* Priority (COS). */
    uint32_t                tunnel_option;/* Tunnel option value. */
    uint32_t                mpls_label;   /* MPLS label. */
    int                     lookup_class; /* Classification class ID. */
} ndi_route_t;

/*
 * L3 host Neighbor Structure for action handle.
 *
 * Contains data on L3 host neighbor for action handle.
 *
 */
typedef struct ndi_neighbor_data_s {
    hal_mac_addr_t  neighbor_mac; /* Next hop MAC addr. */
    hal_vlan_id_t   vlan_id;
    port_t          port_tgid;    /* Port/Trunk group packet is switched to. */
} ndi_neighbor_data_t;

/*
 * Forwarding Database L3 Host Structure.
 *
 * Contains data on L3 host table entries in SAI/NPU
 *
 */
typedef struct ndi_neighbor_s {
    npu_id_t               npu_id;      /* NPU ID packet is switched to. */
    uint32_t               state;
    ndi_route_action       action;
    ndi_vrf_id_t           vrf_id;      /* VRF Id */
    hal_ip_addr_t          ip_addr;     /* Destination host IPv4 or IpV6 Nbr address */
    ndi_rif_id_t           rif_id;      /* Router Interface Id */
    ndi_neighbor_data_t    egress_data; /* neighbor data */
} ndi_neighbor_t;

/**
 * @brief Add a route (IPv4 or IPv6) into NPU Routing table
 *
 * @param route_entry - route entry
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_add(ndi_route_t *route_entry);

/**
 * @brief Delete a route (IPv4 or IPv6) from NPU Routing table
 *
 * @param route_entry - route entry
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_delete(ndi_route_t *route_entry);

/**
 * @brief Set attributes for a route (IPv4 or IPv6) in NPU Routing table
 *
 * @param route_entry - route entry (Flag identifies attribute type)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_set_attribute (ndi_route_t *p_route_entry);

/**
 * @brief Add a neighbor entry (IPv4 or IPv6) into NPU ARP table
 *
 * @param nbr_entry - neighbor entry
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_neighbor_add(ndi_neighbor_t *nbr_entry);

/**
 * @brief Delete a neighbor entry (IPv4 or IPv6) from NPU ARP table
 *
 * @param nbr_entry - neighbor entry
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_neighbor_delete(ndi_neighbor_t *nbr_entry);

/**
 * @brief Create a Next Hop entry (IPv4 or IPv6) in SAI
 *
 * @param nbr_entry - neighbor entry
 *
 * @param[out] nh_handle - next_hop id
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_next_hop_add (ndi_neighbor_t *p_nbr_entry, next_hop_id_t *nh_handle);

/**
 * @brief Delete a Next Hop entry (IPv4 or IPv6) in SAI
 *
 * @param npu_id - npu id
 *
 * @param nh_handle - next hop id
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_next_hop_delete (npu_id_t npu_id, next_hop_id_t nh_handle);


/*
 *  NH Group header starts here
 */


#define NDI_MAX_NH_ENTRIES_PER_GROUP  256
/*
 * Attribute flags for route with multiple NHs info
 *
 * Contains different types attribute flags
 *
 */
typedef enum {
    NDI_ROUTE_NH_GROUP_ATTR_NEXT_HOP_COUNT = (1 << 0),  /* NH count */
    NDI_ROUTE_NH_GROUP_ATTR_TYPE           = (1 << 1),        /* Group type */
    NDI_ROUTE_NH_GROUP_ATTR_NEXT_HOP_LIST  = (1 << 2), /* NH list*/
    NDI_ROUTE_NH_GROUP_ATTR_INVALID        = (1 << 31)
} ndi_route_group_nh_flags;
/*
 * Attribute flags for type of ECMP
 *
 * Contains different types attribute flags
 *
 */
typedef enum {
    NDI_ROUTE_NH_GROUP_TYPE_ECMP        = (1 << 0),  /* ECMP*/
    NDI_ROUTE_NH_GROUP_TYPE_WECMP       = (1 << 1), /* Weigted ECMP */
    NDI_ROUTE_NH_GROUP_TYPE_INVALID     = (1 << 31)
} ndi_route_group_nh_type;

/*
 * @brief the Nexthop Group  data structure
 *
 * Nexthop Group Structure
 *
 * Contains data on NH Group table entries in SAI.
 */

typedef struct ndi_nh_group_s {
    npu_id_t                npu_id;       /* NPU ID. */
    ndi_route_group_nh_flags flags;       /* NH group flags */
    ndi_route_group_nh_type group_type;/* NH group type flags */
    ndi_vrf_id_t            vrf_id;       /* VRF Id */
    hal_ip_addr_t           prefix;       /* Prefix address */
    uint32_t                mask_len;     /* IPv4/ipv6 subnet mask length*/
                                          /* List of nexthops */
    struct {
        next_hop_id_t       id;
        uint32_t            weight;
    } nh_list[NDI_MAX_NH_ENTRIES_PER_GROUP];
    uint32_t                nhop_count;      /* NH count */
    next_hop_id_t           nh_group_handle; /* Nexthop group handle */
} ndi_nh_group_t;


/**
 * @brief Create a Next-Hop Group for ECMP groups
 *
 * @param p_nh_group_entry - NH Group entry
 * @param nh_group_handle - Next Hop Group ID(OUT)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_next_hop_group_create (ndi_nh_group_t *p_nh_group_entry,
                                             next_hop_id_t *nh_group_handle);

/**
 * @brief Delete a Next-Hop Group for ECMP groups
 *
 * @param npu_id - NPU ID
 * @param nh_group_handle - Next Hop Group ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_next_hop_group_delete (npu_id_t npu_id,
                            next_hop_id_t nh_group_handle);

/**
 * @brief Set group attribute for  a Next-Hop Group for ECMP groups
 *
 * @param p_nh_group_entry - NH Group entry
 * @param nh_group_handle - Next Hop Group ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_set_next_hop_group_attribute (
                        ndi_nh_group_t *p_nh_group_entry,
                        next_hop_id_t nh_group_handle);

/**
 * @brief Get group attribute for a Next-Hop Group for ECMP groups
 *
 * @param p_nh_group_entry - NH Group entry
 * @param nh_group_handle - Next Hop Group ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_get_next_hop_group_attribute (
                          ndi_nh_group_t *p_nh_group_entry,
                          next_hop_id_t nh_group_handle);

/**
 * @brief Add  Nexthop(s) to Next-Hop ECMP Group
 *
 * @param p_nh_group_entry - NH Group entry
 * @param nh_group_handle - Next Hop Group ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_add_next_hop_to_group (ndi_nh_group_t *p_nh_group_entry,
                                                next_hop_id_t nh_group_handle);

/**
 * @brief Delete Nexthop(s) from a  Next-Hop ECMP Group
 *
 * @param p_nh_group_entry - NH Group entry
 * @param nh_group_handle - Next Hop Group ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_delete_next_hop_from_group (ndi_nh_group_t *p_nh_group_entry,
                                                    next_hop_id_t nh_group_handle);

/**
 *  \}
 */

#ifdef __cplusplus
}
#endif
#endif
