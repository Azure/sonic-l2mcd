
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
 * filename: nas_ndi_mirror.h
 */


#ifndef NAS_NDI_MIRROR_H_
#define NAS_NDI_MIRROR_H_


#include "std_error_codes.h"
#include "nas_ndi_common.h"
#include "dell-base-mirror.h"
#include "ds_common_types.h"
#include "dell-base-common.h"
#include "nas_types.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup NDIAPIMirror NDI API - Mirror functionality
 *
 *  \{
 */

typedef ndi_obj_id_t ndi_mirror_id_t;

typedef struct {
    ndi_port_t src_port;                /* Mirroring Source Port */
    BASE_CMN_TRAFFIC_PATH_t direction;  /* Traffic Direction of Source Ports in which Mirroring is to be enabled */
}ndi_mirror_src_port_t;

/*
 * @brief NDI Mirror Entry Structure
 * Contains information to create Mirroring session in SAI
 */

typedef struct {
    ndi_mirror_id_t ndi_mirror_id;          /* Mirror Id returned by SAI */
    BASE_MIRROR_MODE_t mode;                /* Mirror Mode (SPAN,RSPAN,ERSPAN) */
    ndi_port_t dst_port;                    /* Mirror to Port */
    hal_ip_addr_t src_ip;                   /* ERSPAN Source IP */
    hal_ip_addr_t dst_ip;                   /* ERSPAN Destination IP */
    hal_mac_addr_t src_mac;                 /* ERSPAN Source MAC */
    hal_mac_addr_t dst_mac;                 /* ERSPAN Destination MAC */
    hal_vlan_id_t vlan_id;                  /* VLAN ID for RSPAN/ERSPAN */
    ndi_obj_id_t ndi_lag_id;                /* NDI LAG Id received as opaque data */
    bool is_dest_lag;                       /* flag to indicate destination is physical
                                               or lag interface in npu */
}ndi_mirror_entry_t;


/**
 * @brief Create a new mirroring session in the NPU
 *
 * @param entry - ndi_mirror_entry_t which contains mirror
 *                session attributes
 * @return - STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_mirror_create_session(ndi_mirror_entry_t * entry);


/**
 * @brief Delete an existing mirroring session in the NPU
 *
 * @param entry - ndi_mirror_entry_t which contains all the mirror
 *                session attributes
 * @return - STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_mirror_delete_session(ndi_mirror_entry_t * entry);


/**
 * @brief Update an existing mirroring session in the NPU
 *
 * @param entry - ndi_mirror_entry_t which contains all the mirror
 *                session attributes
 * @param attr_id- Id of the attribute to be updated
 * @return - STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_mirror_update_session(ndi_mirror_entry_t * entry, BASE_MIRROR_ENTRY_t attr_id);


/**
 * @brief Update direction of source port in an existing
 *        mirroring session in the NPU
 *
 * @param entry - ndi_mirror_entry_t which contains all the mirror
 *                session attributes
 * @param port -  contains npu id, port id and direction
 * @param enable - if true enable, else disable.
 * @return - STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_mirror_update_direction(ndi_mirror_entry_t *entry, ndi_mirror_src_port_t port , bool enable);


/**
 * @brief Get existing mirroring session information from the NPU
 *
 * @param entry - ndi_mirror_entry_t which contains all the mirror
 *                session attributes
 * @param npu_id - NPU Identifier
 * @param ndi_mirror_id - NDI Mirror Id
 * @return - STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_mirror_get_session(ndi_mirror_entry_t * entry, npu_id_t npu_id,ndi_mirror_id_t ndi_mirror_id);


/**
 *  \}
 */

#ifdef __cplusplus
}
#endif

#endif /* NAS_NDI_MIRROR_H_ */
