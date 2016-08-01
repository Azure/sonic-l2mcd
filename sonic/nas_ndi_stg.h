
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
 * filename: nas_ndi_stg.h
 */

#ifndef NAS_NDI_STG_H_
#define NAS_NDI_STG_H_


#include "std_error_codes.h"
#include "ds_common_types.h"
#include "dell-base-stg.h"
#include "nas_ndi_common.h"
#include "nas_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef ndi_obj_id_t ndi_stg_id_t;

/** \defgroup NDIAPISTG NDI API - STG functionality
 *
 *  \{
 */


/**
 * @brief Create a new STG instance in the NPU
 * @param npu_id - NPU id where STG instance is to be created
 * @param[out] stg id- stg id to be filled in
 * @return STD_ERR_OK if operation is successful otherwise a different
 *          error code is returned.
 */
t_std_error ndi_stg_add(npu_id_t npu_id,ndi_stg_id_t * stg_id);


/**
 * @brief Delete an existing STG instance from the NPU
 * @param npu_id - NPU id where STG instance is to be deleted
 * @param stg id - stg id to be deleted
 * @return STD_ERR_OK if operation is successful otherwise a different
 *          error code is returned.
 */
t_std_error ndi_stg_delete(npu_id_t npu_id, ndi_stg_id_t stg_id);


/**
 * @brief Add/Delete VLANs to the STG id in the NPU
 * @param npu_id - NPU id where vlan needs to be added/deleted to/from stg id
 * @param stg id - stg id - default stg id if vlan is to be removed else
 *                    new stg id where it needs to be added
 * @param vlan_id - vlan id to be added or deleted
 * @return STD_ERR_OK if operation is successful otherwise a different
 *          error code is returned.
 */
t_std_error ndi_stg_update_vlan(npu_id_t npu_id, ndi_stg_id_t  stg_id, hal_vlan_id_t vlan_id);


/**
 * @brief Set the STP state of the port associated with the STG id in the NPU
 * @param npu_id - NPU id of the STG instance
 * @param stg id - stg id
 * @param port_id - port id
 * @param port_stp_state - STP state
 * @return STD_ERR_OK if operation is successful otherwise a different
 *          error code is returned.
 */
t_std_error ndi_stg_set_stp_port_state(npu_id_t npu_id, ndi_stg_id_t stg_id, npu_port_t port_id,
                                BASE_STG_INTERFACE_STATE_t port_stp_state);


/**
 * @brief Get the STP state of the port associated with the STG id in the NPU
 * @param npu_id - NPU id of the STG instance
*  @param stg id  - stg id
 * @param port_id  - port id
 * @param[out] port_stp_state- STP state to be filled in
 * @return STD_ERR_OK if operation is successful otherwise a different
 *          error code is returned.
 */
t_std_error ndi_stg_get_stp_port_state(npu_id_t npu_id, ndi_stg_id_t stg_id, npu_port_t port_id,
                                BASE_STG_INTERFACE_STATE_t *port_stp_state);


/**
 * @brief Get the default STG id created in the NPU
 *
 * @param npu_id - NPU Id from where stg id is to be get
 * @param[out] stg_id - stg id to be filled in
 * @param[out] vlan_id - vlan id associated with default instance
 *
 * @return STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_stg_get_default_id(npu_id_t npu_id,ndi_stg_id_t *stg_id,hal_vlan_id_t * vlan_id);

/**
 *  \}
 */

#ifdef __cplusplus
}
#endif

#endif /* NAS_NDI_STG_H_ */
