
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
 * filename: nas_ndi_router_interface.h
 */


#ifndef __NAS_NDI_RIF_H
#define __NAS_NDI_RIF_H

#include "std_error_codes.h"
#include "ds_common_types.h"
#include "nas_ndi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup NDI API - Router Interface (RIF) & Virtual Router (VR) Functionality
 *
 *  \{
 */

#define NDI_MAX_RIF_ATTR    10

/*
 * RIF ID type
 */
typedef ndi_obj_id_t  ndi_rif_id_t;
typedef ndi_obj_id_t  ndi_vrf_id_t;


typedef enum {
    NDI_RIF_TYPE_PORT,        /* RIF type Port */
    NDI_RIF_TYPE_VLAN,        /* RIF type Vlan */
    NDI_RIF_TYPE_LAG          /* RIF type Lag  */
} ndi_rif_type;

/*
 * Attribute flags for NDI RIF info
 *
 *  Contains NDI Routing Interface (RIF) attribute flags
 *
 */
typedef enum {
    NDI_RIF_ATTR_VIRTUAL_ROUTER_ID  = (1 << 0), /* Mandatory attribute */
    NDI_RIF_ATTR_TYPE  = (1 << 1),         /* Mandatory attribute */
    NDI_RIF_ATTR_PORT_ID = (1 << 2),      /* Mandatory attribute for port type*/
    NDI_RIF_ATTR_VLAN_ID  = (1 << 3),     /* Mandatory attribute for VLAN type */
    NDI_RIF_ATTR_SRC_MAC_ADDRESS = (1 << 4), /* MAC Address [hal_mac_addr_t] */
    NDI_RIF_ATTR_ADMIN_V4_STATE  = (1 << 5), /* Admin V4 state (default TRUE) */
    NDI_RIF_ATTR_ADMIN_V6_STATE  = (1 << 6), /* Admin V6 state (default TRUE) */
    NDI_RIF_ATTR_MTU            = (1 << 7), /* MTU */
    NDI_RIF_ATTR_INVALID        = (1 << 31)
} ndi_rif_flags;


/*
 * @brief the NDI RIF data structure
 *
 * NDI RIF Router Interface Structure
 *
 * Contains NDI data on RIF entry in SAI.
 */

typedef struct ndi_rif_entry_s {
    npu_id_t                npu_id;       /* NPU ID. */
    ndi_rif_flags           flags;       /* RIF attribute flags */
    /** Mandatory RIF attributes */
    ndi_rif_id_t            rif_id;    /* Router Interface Id */
    ndi_vrf_id_t            vrf_id;       /* VRF Id . */
    ndi_rif_type            rif_type;
    union {
        ndi_port_t          port_id;
        hal_vlan_id_t       vlan_id;
        ndi_obj_id_t        lag_id;
    } attachment;
    /** Optional RIF attributes */
    hal_mac_addr_t          src_mac;
    bool                    v4_admin_state;
    bool                    v6_admin_state;
    uint_t                  mtu;
} ndi_rif_entry_t;


/*
 * @brief Create a Route Interface (RIF) instance with a set of attributes passed to SAI
 *
 * @param rif_entry - rif entry (Flag identifies attribute type)
 * @param rif_id - rif id
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_rif_create (ndi_rif_entry_t *rif_entry, ndi_rif_id_t *rif_id);

/*
 * @brief Delete a Route Interface (RIF) instance from SAI
 *
 * @param npu_id - NPU ID
 * @param rif_id - rif id
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_rif_delete(npu_id_t npu_id, ndi_rif_id_t rif_id);

/**
 * @brief Set attributes for a RIF in SAI
 *
 * @param rif_entry - rif entry (Flags identify attribute type)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_rif_set_attribute (ndi_rif_entry_t *rif_entry);

/**
 * @brief Get attributes for a RIF in SAI
 *
 * @param rif_entry - rif entry (Flags identify attribute type)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_rif_get_attribute (ndi_rif_entry_t *rif_entry);


/*
 * Virtual Router (VR) Functionality
 */

#define NDI_MAX_VR_ATTR    10

/*
 * Attribute flags for NDI VR info
 *
 *  Contains NDI Virtual Router(VR) attribute flags
 *
 */
typedef enum {
    NDI_VR_ATTR_ADMIN_V4_STATE  = (1 << 0), /* Admin V4 state (default TRUE) */
    NDI_VR_ATTR_ADMIN_V6_STATE  = (1 << 1), /* Admin V6 state (default TRUE) */
    NDI_VR_ATTR_SRC_MAC_ADDRESS = (1 << 2),  /* MAC Address [hal_mac_addr_t] */
    /* Action for Packets with TTL 0 or 1 [ndi_route_action]
      (default to NDI_ROUTE_PACKET_ACTION_TRAPCPU) */
    NDI_VR_ATTR_VIOLATION_TTL1_ACTION  = (1 << 3),
    /* Action for Packets with IP options [ndi_route_action]
     * (default to NDI_ROUTE_PACKET_ACTION_TRAPCPU) */
    NDI_VR_ATTR_VIOLATION_IP_OPTIONS = (1 << 4),
    NDI_VR_ATTR_INVALID        = (1 << 31)
} ndi_vr_flags;


/*
 * @brief the NDI VR data structure
 *
 * Virtual Router (VR) Structure
 *
 * Contains data on VR entry in SAI.
 */

typedef struct ndi_vr_entry_s {
    npu_id_t                npu_id;       /* NPU ID. */
    ndi_vrf_id_t            vrf_id;       /* VRF Id . */
    hal_mac_addr_t          src_mac;      /* VR or system mac */
    ndi_vr_flags            flags;        /* NDI VR flags */
    bool                    v4_admin_state;  /* on by default */
    bool                    v6_admin_state; /* on by default */
    int32_t                 ttl1_action;
    int32_t                 violation_ip_options;
} ndi_vr_entry_t;

/*
 * @brief Create a Virtual Router (VR) instance with a set of attributes passed to SAI
 * @param vr_entry - vr entry
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_vr_create (ndi_vr_entry_t *vr_entry, ndi_vrf_id_t *vrf_id);

/*
 * @brief Delete a Virtual Router (VR) instance from SAI
 * @param npu_id - NPU ID
 * @param vrf_id - vrf id (VR ID)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_vr_delete(npu_id_t npu_id, ndi_vrf_id_t vrf_id);

/**
 * @brief Set attributes for a VR in SAI
 *
 * @param vr_entry - vr entry (Flags identify attribute type)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_vr_set_attribute (ndi_vr_entry_t *vr_entry);

/**
 * @brief Get attributes for a VR in SAI
 *
 * @param vr_entry - vr entry (Flags identify attribute type)
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_route_vr_get_attribute (ndi_vr_entry_t *vr_entry);

/**
 *  \}
 */

#ifdef __cplusplus
}
#endif
#endif
