
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
 * filename: nas_ndi_lag.h
 */


#ifndef NAS_NDI_LAG_H_
#define NAS_NDI_LAG_H_

#include "std_error_codes.h"
#include "ds_common_types.h"
#include "nas_ndi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup LAG NDIAPI
 *
 This file consists of the NDI API's to create,delete and manage ports to LAG Group.

 Important APIs are:
 @{
     ndi_create_lag
     ndi_delete_lag
     ndi_add_ports_to_lag
     ndi_del_ports_from_lag

 */

/**
 * Create a Lag Group
 *
 * @param npu_id - NPU that contains lag group
 *
 * @param ndi_lag_id - NDI lag group reference ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_create_lag(npu_id_t npu_id,ndi_obj_id_t *ndi_lag_id);

/**
 * Delete a Lag group
 *
 * @param npu_id - NPU that contains lag group
 *
 * @param ndi_lag_id - NDI lag group reference ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_delete_lag(npu_id_t npu_id, ndi_obj_id_t ndi_lag_id);

/**
 * Add ports to lag
 *
 * @param npu_id - NPU that contains lag group
 *
 * @param ndi_lag_id - NDI lag group reference ID
 *
 * @param lag_port_list - List of ports to be added to lag
 *
 * @param ndi_lag_member_id - NDI lag member reference ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */

t_std_error ndi_add_ports_to_lag(npu_id_t npu_id, ndi_obj_id_t ndi_lag_id,ndi_port_list_t *lag_port_list,
                   ndi_obj_id_t *ndi_lag_member_id);

/**
 * Delete ports from lag
 *
 * @param npu_id - NPU that contains lag group
 *
 * @param ndi_lag_member_id- NDI lag member reference ID
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */

t_std_error ndi_del_ports_from_lag(npu_id_t npu_id,ndi_obj_id_t ndi_lag_member_id);

/**
 * Enable/Disable traffic on Lag member port
 *
 * @param npu_id - NPU that contains lag group
 *
 * @param ndi_lag_member_id - NDI lag member reference ID
 *
 * @param egress_disable - enable or disable Traffic on the port
 *
 * @return STD_ERR_OK if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_set_lag_member_attr(npu_id_t npu_id, ndi_obj_id_t ndi_lag_member_id,
                bool egress_disable);

/**
 * get traffic enable/disable mode of lag member port
 *
 * @param npu_id - npu that contains lag group
 *
 * @param ndi_lag_member_id - ndi lag member reference id
 *
 * @param egress_disable - pointer to store traffic enable/disable mode of the port
 *
 * @return std_err_ok if operation is successful otherwise a different
 *  error code is returned.
 */
t_std_error ndi_get_lag_member_attr(npu_id_t npu_id, ndi_obj_id_t ndi_lag_member_id,
                bool *egress_disable);

/**
@}
*/

#ifdef __cplusplus
}
#endif
#endif /* NAS_NDI_LAG_H_ */
