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

#ifndef _APPLOG_H_
#define _APPLOG_H_

#include <stdio.h>
#include <syslog.h>
#include <stdarg.h>

#define APP_LOG_LEVEL_NONE            (-1)
#define APP_LOG_LEVEL_EMERG           (0) /* system is unusable */
#define APP_LOG_LEVEL_ALERT           (1) /* action must be taken immediately */
#define APP_LOG_LEVEL_CRIT            (2) /* critical conditions */
#define APP_LOG_LEVEL_ERR             (3) /* error conditions */
#define APP_LOG_LEVEL_WARNING         (4) /* warning conditions */
#define APP_LOG_LEVEL_NOTICE          (5) /* normal but significant condition */
#define APP_LOG_LEVEL_INFO            (6) /* informational */
#define APP_LOG_LEVEL_DEBUG           (7) /* debug-level messages */

#define APP_LOG_LEVEL_MIN             (APP_LOG_LEVEL_EMERG)
#define APP_LOG_LEVEL_DEFAULT         (APP_LOG_LEVEL_CRIT)
#define APP_LOG_LEVEL_MAX             (APP_LOG_LEVEL_DEBUG)

#define APP_LOG_STATUS_OK             (0)
#define APP_LOG_STATUS_FAIL           (-1)
#define APP_LOG_STATUS_INVALID_LEVEL  (-2)
#define APP_LOG_STATUS_LEVEL_DISABLED (-3)

#define APP_LOG_INIT                  applog_init
#define APP_LOG_DEINIT                applog_deinit
#define APP_LOG_SET_LEVEL(level)      applog_set_config_level(level)

#define MLD_LOGLEVEL1          APP_LOG_LEVEL_EMERG
#define MLD_LOGLEVEL2          APP_LOG_LEVEL_ALERT
#define MLD_LOGLEVEL3          APP_LOG_LEVEL_CRIT
#define MLD_LOGLEVEL4          APP_LOG_LEVEL_ERR
#define MLD_LOGLEVEL5          APP_LOG_LEVEL_WARNING
#define MLD_LOGLEVEL6          APP_LOG_LEVEL_NOTICE
#define MLD_LOGLEVEL7          APP_LOG_LEVEL_INFO
#define MLD_LOGLEVEL8          APP_LOG_LEVEL_DEBUG
#define MLD_LOGLEVEL9          APP_LOG_LEVEL_DEBUG

/* add other logs before this line */
#define MLD_LOG(_level, afi, ...) applog_write(_level, ##__VA_ARGS__)
#define FN __FUNCTION__
#define LN __LINE__

extern int applog_init();
extern int applog_deinit();
extern int applog_set_config_level(int level);
extern int applog_get_config_level();
extern int applog_get_init_status();
extern int applog_write(int priority, const char *fmt, ...);

#endif /*_APPLOG_H_*/

