
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
 * filename: nas_ndi_port.h
 */


#ifndef __NAS_NDI_PORT_H
#define __NAS_NDI_PORT_H

#include "std_error_codes.h"
#include "dell-base-if-phy.h"
#include "ietf-interfaces.h"
#include "nas_ndi_common.h"
#include "dell-base-platform-common.h"
#include "dell-base-statistics.h"
#include "dell-base-common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup NDIAPIPort NDI API - Port Functionality
 *
 *  \{
 */

/**
 * This function register port link state callback function with NDI.
 * @param reg_fn callback function for port link state notification
 * @return standard error
 */
t_std_error ndi_port_oper_state_notify_register(ndi_port_oper_status_change_fn reg_fn);


/**
 * This function retrieves port stats from SAI.
 * @param npu_id npu id
 * @param port_id port id
 * @param ndi_stats_counter_ids Pointer to nas_stat_id_t array
 * @param stats_val Pointer to array of counters
 * @param len number of counters
 * @return STD_ERR_OK if successful otherwise an error code indicating the failure
 */
t_std_error ndi_port_stats_get(npu_id_t npu_id, npu_port_t port_id,
                               ndi_stat_id_t *ndi_stats_counter_ids,
                               uint64_t* stats_val, size_t len);


/**
 * This function sets port admin state in the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param admin_state Admin State UP/DOWN
 * @return standard error
 */
t_std_error ndi_port_admin_state_set(npu_id_t npu_id, npu_port_t port_id,
                        bool admin_state);

/**
 * This function gets port admin state from the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param admin_state Admin State UP/DOWN
 * @return standard error
 */
t_std_error ndi_port_admin_state_get(npu_id_t npu_id, npu_port_t port_id,
                     IF_INTERFACES_STATE_INTERFACE_ADMIN_STATUS_t *admin_state);

/**
 * This function gets port link state from the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param link_state Link State UP/DOWN
 * @return standard error
 */
t_std_error ndi_port_link_state_get(npu_id_t npu_id, npu_port_t port_id,
        ndi_intf_link_state_t *link_state);


/**
 * Get the port's physical MTU value.
 * @param npu_id the npu id
 * @param port_id the port id
 * @param mtu the returned MTU as a unsigned integer number
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_mtu_get(npu_id_t npu_id, npu_port_t port_id, uint_t *mtu);


/**
 * Set the port's physical MTU value.
 * @param npu_id the npu id
 * @param port_id the port id
 * @param mtu the MTU to set in unsigned integer
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_mtu_set(npu_id_t npu_id, npu_port_t port_id, uint_t mtu);

#define NDI_PORT_SUPPORTED_SPEED_MAX 7
/**
 * This function gets supported port speed list from NPU.
 * @param npu_id npu id
 * @param ndi_port port id
 * @param speed_count number of suported speeds
 * @param speed_list supported port speed list
 * @return standard error
 */
t_std_error ndi_port_supported_speed_get(npu_id_t npu_id, npu_port_t ndi_port,
        size_t *speed_count, BASE_IF_SPEED_t *speed_list);
/**
 * This function sets port speed in the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param speed port speed
 * @return standard error
 */
t_std_error ndi_port_speed_set(npu_id_t npu_id, npu_port_t port_id,  BASE_IF_SPEED_t speed);

/**
 * This function gets port speed from NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param speed port speed
 * @return standard error
 */
t_std_error ndi_port_speed_get(npu_id_t npu_id, npu_port_t port_id, BASE_IF_SPEED_t *speed);

/**
 * This function sets physical media type in the NPU baesd on the QSFP/SFP plugged-in.
 * @param npu_id npu id
 * @param port_id port id
 * @param media Physical Media type of the port
 * @return standard error
 */
t_std_error ndi_port_media_type_set(npu_id_t npu_id, npu_port_t port_id, PLATFORM_MEDIA_TYPE_t media);

/** This function updates port attribute to any of the three possible combinations of:
 *         untagged only
 *         tagged only
 *         both untagged and tagged
 *
 * @param npu_id npu id
 * @param port_id port id
 * @param mode the tagged mode selecting one of the 3 valid options
 * @return standard error
 */

t_std_error ndi_port_set_untagged_port_attrib(npu_id_t npu_id,
                                              npu_port_t port_id,
                                              BASE_IF_PHY_IF_INTERFACES_INTERFACE_TAGGING_MODE_t mode);

/** This function gets the port vlan accepting mode - one of three possible combinations:
 *         untagged only
 *         tagged only
 *         both untagged and tagged
 *
 * @param npu_id npu id
 * @param port_id port id
 * @param mode the tagged mode selecting one of the 3 valid options
 * @return standard error
 */

t_std_error ndi_port_get_untagged_port_attrib(npu_id_t npu_id,
                                              npu_port_t port_id,
                                              BASE_IF_PHY_IF_INTERFACES_INTERFACE_TAGGING_MODE_t *mode);

/** This function sets the default vid for port
 *  Set it when the port is untagged .
 * @param npu_id npu id
 * @param port_id port id
 * @vlan_id Vlan ID
 * @return standard error
 */

t_std_error ndi_set_port_vid(npu_id_t npu_id, npu_port_t port_id,
                             hal_vlan_id_t vlan_id);

/** This function returns max port in the npu
 * @param npu_id npu id
 * @return max port in the npu
 */
size_t ndi_max_npu_port_get(npu_id_t npu);

/** function for checking if the port is invalid
 * @param npu_id npu id
 * @param port_id port id
 * @return true if port is valid otherwise false
 */
bool ndi_port_is_valid(npu_id_t npu_id, npu_port_t npu_port);

/** function to get the list of hwport belonging to the ndi_port
 * @param npu_id npu id
 * @param ndi_port npu port id
 * @param[out] hwport hw port belong to the ndi_port
 * @return standard error
 */
t_std_error ndi_hwport_list_get(npu_id_t npu_id, npu_port_t ndi_port, uint32_t *hwport);

/**  function for setting breakout mode for a ndi_port *
 * @param[in] npu_id npu id
 * @param[in] ndi_port port id
 * @param[in] mode breakout mode type
 * @param[in] effected_ports the ports that will be changed due to the breakout/breakin
 * @param[in] len the length of the effeted port list
 * @return standard error
 * */
t_std_error ndi_port_breakout_mode_set(npu_id_t npu_id, npu_port_t ndi_port,
        BASE_IF_PHY_BREAKOUT_MODE_t mode, npu_port_t *effected_ports, size_t port_len);

/**  function for getting the current breakout mode for a ndi_port
 * @param[in] npu_id the npu id
 * @param[in] ndi_port the port id
 * @param[out] mode the pointer to hold the breakout mode
 * @return STD_ERR_OK or a specific return code indicating what the error was
 * */
t_std_error ndi_port_breakout_mode_get(npu_id_t npu_id, npu_port_t ndi_port,  BASE_IF_PHY_BREAKOUT_MODE_t *mode);

/**  function for getting list of breakout mode supported.
 * @param[in] npu_id npu id
 * @param[in] ndi_port port id
 * @param[inout] mode_count pointer to the number of modes supported by the port
 * @param[out] mode_list breakout mode lists
 * @return standard error
 */
t_std_error ndi_port_supported_breakout_mode_get(npu_id_t npu_id, npu_port_t ndi_port,
        int *mode_count, BASE_IF_PHY_BREAKOUT_MODE_t *mode_list);

/** function for registering port events [PORT ADD/DELETE] callback to NDI
 * @param[in] npu_id npu id
 * @param[in] func callback functions registered with NDI
 * @return standard error
 */
t_std_error ndi_port_event_cb_register(npu_id_t npu_id, ndi_port_event_update_fn func);

/** function for getting npu cpu port ID
 * @param[in] npu_id npu id
 * @param[out] cpu_port CPU port for this NPU
 * @return standard error
 */
t_std_error ndi_cpu_port_get(npu_id_t npu_id, npu_port_t *cpu_port);

/**
 * Get the port's MAC Learning Mode
 * @param npu_id - npu id of port
 * @param port_id - port id
 * @param mode - returned MAC learn mode of port
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_mac_learn_mode_get(npu_id_t npu_id, npu_port_t port_id,
                                        BASE_IF_PHY_MAC_LEARN_MODE_t *mode);

/**
 * Set the port's MAC Learning Mode
 * @param npu_id - npu id of port
 * @param port_id - port id
 * @param mode - MAC learn mode to be set for port
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_mac_learn_mode_set(npu_id_t npu_id, npu_port_t port_id,
                                        BASE_IF_PHY_MAC_LEARN_MODE_t mode);

/**
 * Set the port in loopback mode
 * @param npu_id - npu id of port
 * @param port_id - port id
 * @param mode - loopback mode
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_loopback_set(npu_id_t npu_id, npu_port_t port_id,
                                        BASE_CMN_LOOPBACK_TYPE_t loopback);
/**
 * Get the port's loopback mode
 * @param npu_id - npu id of port
 * @param port_id - port id
 * @param mode - loopback mode
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_loopback_get(npu_id_t npu_id, npu_port_t port_id,
                                        BASE_CMN_LOOPBACK_TYPE_t *loopback);


/**
 * Clear all the port stats
 * @param npu_id - npu id of port
 * @param port_id - port id
 * @return STD_ERR_OK if successful otherwise an error code
 */
t_std_error ndi_port_clear_all_stat(npu_id_t npu_id, npu_port_t port_id);

/**
 * Enable/Disable ingress filtering
 * @param npu_id - npu id of port
 * @param port_id - port id
 * @return STD_ERR_OK if successful otherwise an error code
 */

t_std_error ndi_port_set_ingress_filtering(npu_id_t npu_id, npu_port_t port_id,
                                           bool ing_filter);
/**
 * This function sets port auto neg in the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param enable if true then enable auto neg
 * @return standard error
 */

t_std_error ndi_port_auto_neg_set(npu_id_t npu_id, npu_port_t port_id, bool enable);
/**
 * This function gets port auto neg  from the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param enable if true then auto neg is enabled
 * @return standard error
 */
t_std_error ndi_port_auto_neg_get(npu_id_t npu_id, npu_port_t port_id, bool *enable);

/**
 * This function sets port duplex mode in the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param duplex: FULL/HALF/AUTO
 * @return standard error
 */

t_std_error ndi_port_duplex_set(npu_id_t npu_id, npu_port_t port_id,
        BASE_CMN_DUPLEX_TYPE_t duplex);
/**
 * This function gets port's duplex mode from the NPU.
 * @param npu_id npu id
 * @param port_id port id
 * @param duplex : FULL/HALF
 * @return standard error
 */
t_std_error ndi_port_duplex_get(npu_id_t npu_id, npu_port_t port_id,
                   BASE_CMN_DUPLEX_TYPE_t *duplex);

/**
 *  \}
 */

#ifdef __cplusplus
}
#endif
#endif
