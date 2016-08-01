
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
 * filename: nas_ndi_plat_stat.h
 */


#ifndef __NAS_NDI_PLAT_STAT_H
#define __NAS_NDI_PLAT_STAT_H

#include "std_error_codes.h"
#include "dell-base-statistics.h"
#include <stdint.h>

typedef enum{
    NAS_STAT_IF=0,
    NAS_STAT_VLAN,
}nas_stat_type_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   This API returns Maximum Statistics id supported for nas_stat_type_t.
 * @param   [in]  type - is the nas_stat_type_t
 * @param   [out] len  - is the maximum stat ids supported by NPU
 * @return  STD_ERR_OK if success otherwise valid error code is returned
 */
t_std_error ndi_plat_get_ids_len(nas_stat_type_t type, unsigned int * len);


/**
 * @brief   This API returns NPU supported statistics counter ids
 * @param   [in] list is the list being returned which holds base statistics id which is supported
 *               by NPU
 * @param   [in/out] len is the length of the list passed, and after function returns length of
 *                   the list filled
 * @param
 * @return  STD_ERR_OK if success otherwise valid error code is returned
 */
t_std_error ndi_plat_port_stat_list_get(uint64_t * list, unsigned int *len);

/**
 * @brief   This API returns NPU supported statistics counter ids
 * @param   [in] list is the list being returned which holds base statistics id which is supported
 *               by NPU
 * @param   [in/out] len is the length of the list passed, and after function returns length of
 *                   the list filled
 * @return  STD_ERR_OK if success otherwise valid error code is returned
 */

t_std_error ndi_plat_vlan_stat_list_get(uint64_t * list,unsigned int *len);

#ifdef __cplusplus
}
#endif

#endif /* __NAS_NDI_PLAT_STAT_H */
