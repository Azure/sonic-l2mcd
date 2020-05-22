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
#define IPVRF_MAX_USER_DEFINED_VRFS      1024
#define MVRF_DEFAULT_VRF_ID  L2MCD_DEFAULT_VRF_IDX
#define IPVRF_MAX_VRF_IDX                (IPVRF_MAX_USER_DEFINED_VRFS + 1)
#define IPVRF_INVALID_VRF_IDX		(IPVRF_MAX_VRF_IDX+1)
#define IPVRF_DEFAULT_VRF_IDX		     MVRF_DEFAULT_VRF_ID
typedef enum IP_AFI_TYPES
{
	IP_IPV4_AFI	= 0x0001,
	IP_IPV6_AFI	= 0x0002,
	IP_AFI_SIZE	= 2
} IP_AFI_TYPES;
#endif
