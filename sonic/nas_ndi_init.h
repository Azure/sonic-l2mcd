
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
 * filename: nas_ndi_init.h
 */


#ifndef __NAS_NDI_INIT_H
#define __NAS_NDI_INIT_H

#include "std_error_codes.h"
#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup NDIAPIINIT NDI API - NPU Initialization Functionality
 *
 *  \{
 */

/**
 * This function initializes NDI data-structure based on the platform and chip config file
 * and then initializes appropriate SAI library based on the CHIP vendor and type for each of the
 * NPU. Then it initializes all NPUs by calling SAI initialization function as per SAI guideline.
 * @return  std_error
 */
t_std_error nas_ndi_init(void);

/**
 *  \}
 */

#ifdef __cplusplus
}
#endif
#endif 

