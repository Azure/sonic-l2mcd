
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
 * filename: hal_shell.h
 */

/*
 * hal_shell.h
 */

#ifndef HAL_SHELL_H_
#define HAL_SHELL_H_

#include "std_type_defs.h"
#include "nas_types.h"
#include "std_error_codes.h"
#include "std_utils.h"

#include <stdbool.h>
#include <stddef.h>

/**
 * @defgroup NDICommonShell NDI Common - Shell Command Access
 * Functions used to enable and define a debug shell for the NDI daemon (HAL daemon).
 * Allow access to any switch/NPU vendor shell SDK as well as addition of new / customized shell functions
 * @{
 */
/**
 * This function call prototype can be added by anyone that wants to create their own HAL Shell CLI.
 * The cmd_string will need to be checked to determine if the function call should handle it.
 * If the function does handle the cmd_string, then the function call should return true otherwise false.
 * @param param is the parameter that the function call is registered with
 * @param cmd_string the command string to parse to see if it is something that this function call will handle
 * @return true if the cmd_string is meant to be processed by this function, otherwise false
 */
typedef bool (*hal_shell_check_run_function)(void * param, const char *cmd_string);

/**
 * This function will just process a specific shell command. When registering this function call the caller
 * would have already specified the actual name of the shell command and therefore the cmd_string is just the
 * Arguments to the shell function.
 * eg.
 *      shell to print a route table
 *      ::print-routes all
 *      this function would receive the string " all" (everything after the "print-routes")
 * @param handle is a parsed string handle to process command line arguments
 */
typedef void (*hal_shell_function)(std_parsed_string_t handle);

/**
 * This will add a function call to the shell command list.  Any function added here can be called
 * from the shell by prefixing the command with a ::
 * @param param the context to the function call
 * @param fun the function to register
 * @return true command was added, false otherwise
 */
bool hal_shell_cmd_add_flexable(void * param, hal_shell_check_run_function fun);

/**
 * This will register a shell function against a specific shell command (name).
 * For instance... if the designer wants to create a shell command called "print-route" they would do
 * something like:
 @verbatim
  static void print_route(const char * param) {
        routes_dump();
  }
  hal_shell_cmd_add("route-print",print_route);
 @endverbatim
 * @param name the string name of the shell command to be added
 * @param fun the function call to be executed
 * @param description the description of the command. Make sure to pass a const char string or to allocate
 * permanent memory if you pass a non const string.
 * @return true command was added, false otherwise
 */
bool hal_shell_cmd_add(const char *name,hal_shell_function fun,const char *description);


/**
 *  This will run a shell command that has been loaded into the (ar) interpreter.  The shell is basic.
 *  the output will be redirected to the standard output.
 *
 *  @param str the string containing the shell command to run.
 */
void hal_shell_run_command(const char *str);

/**
 * @}
 */

#endif /* HAL_SHELL_H_ */
