
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
 * filename: nas_ndi_sflow.h
 */

#ifndef NAS_NDI_SFLOW_H_
#define NAS_NDI_SFLOW_H_

#include "ds_common_types.h"
#include "dell-base-sflow.h"
#include "dell-base-common.h"
#include "std_error_codes.h"
#include "nas_types.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C"{
#endif

/** \defgroup NDIAPIsFlow NDI API - sFLow functionality
 *
 *  \{
 */


typedef ndi_obj_id_t ndi_sflow_id_t;

/**
 * @brief the sFLow data structure
 *
 * Contains data on sFlow session in SAI.
 */
typedef struct{
    npu_id_t npu_id;
    npu_port_t port_id;
    ndi_sflow_id_t ndi_sflow_id;
    uint32_t sampling_rate;
    bool enabled;
    BASE_CMN_TRAFFIC_PATH_t sflow_direction;
}ndi_sflow_entry_t;


/**
 * @brief Enable sFlow packet sampling in NPU for a port
 * @param sflow_entry - sFlow session parameters
 * @return STD_ERR_OK if operation is successful otherwise a different
 *         error code is returned.
 */
t_std_error ndi_sflow_create_session(ndi_sflow_entry_t *sflow_entry);


/**
 * @brief Disable sFlow packet sampling in NPU for a port
 * @param id - ndi_sflow_session id
 * @return STD_ERR_OK if operation is successful otherwise a different
 *         error code is returned.
 */
t_std_error ndi_sflow_delete_session(ndi_sflow_entry_t *sflow_entry);


/**
 * @brief Update one or more attributes of the sFlow session
 * @param sflow_entry - sFlow session parameters
 * @param attr_id - attribute id to be updated
 * @return STD_ERR_OK if operation is successful otherwise a different
 *         error code is returned.
 */
t_std_error ndi_sflow_update_session(ndi_sflow_entry_t *sflow_entry,BASE_SFLOW_ENTRY_t attr_id);

/**
 * @brief Update direction of sampling in an existing sflow session in the NPU
 *
 * @param entry - NDI sFLow entry
 * @param direciton - direction in which sampling is to be enabled/disabled
 * @param enable - if true enable sampling, else disable.
 * @return - STD_ERR_OK if successful, otherwise different error code
 */
t_std_error ndi_sflow_update_direction(ndi_sflow_entry_t *entry,BASE_CMN_TRAFFIC_PATH_t direction, bool enable);


/**
 * @brief Get the sflow entry from NPU for a given NPU and sflow session id
 * @param sflow_entry - sFlow session entry to be filled in
 * @param npu_id - NPU id from where entry is to be fetched
 * @param id - ID of the entry to be fetched
 * @return STD_ERR_OK if operation is successful otherwise a different
 *         error code is returned.
 */
t_std_error ndi_sflow_get_session(ndi_sflow_entry_t *sflow_entry,npu_id_t npu_id,ndi_sflow_id_t id);

/**
 *  \}
 */

#ifdef __cplusplus
}
#endif

#endif /* NAS_NDI_SFLOW_H_ */
