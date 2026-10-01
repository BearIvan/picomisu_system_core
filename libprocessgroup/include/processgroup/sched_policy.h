/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Check if Linux kernel enables CPUSETS feature.
 *
 * Return value: 1 if Linux kernel CONFIG_CPUSETS=y; 0 otherwise.
 */
extern bool cpusets_enabled();

/*
 * Check if Linux kernel enables SCHEDTUNE feature (only available in Android
 * common kernel or Linaro LSK, not in mainline Linux as of v4.9)
 *
 * Return value: 1 if Linux kernel CONFIG_CGROUP_SCHEDTUNE=y; 0 otherwise.
 */
extern bool schedboost_enabled();

/* Keep in sync with THREAD_GROUP_* in frameworks/base/core/java/android/os/Process.java
 * and frameworks/base/core/java/android/os/ProcessSmtEx.java */
typedef enum {
    // Smartisan cgroup freezer (factory PICO OS 5.13.7): the policy set_freeze_policy() and
    // Process.setProcessFreezeGroup() use for a frozen task; the factory name is not known.
    SP_FREEZE = -20,
    // PICO OS 5.13.7 (ProcessSmtEx.THREAD_GROUP_SP_PREFETCH_VR_APP): prefetched VR app,
    // task profile PrefetchLowIoPriority; schedtune/cpuset group prefetch_vr_app.
    SP_PREFETCH_VR_APP = -15,
    // PICO OS 5.13.7 (ProcessSmtEx.THREAD_GROUP_BG_3RD_APP): background third-party app,
    // cpuset bg_3rd_app (task profile ProcessCapacity3rd).
    SP_BG_3RD_APP = -10,
    SP_DEFAULT = -1,
    SP_BACKGROUND = 0,
    SP_FOREGROUND = 1,
    SP_SYSTEM = 2,  // can't be used with set_sched_policy()
    SP_AUDIO_APP = 3,
    SP_AUDIO_SYS = 4,
    SP_TOP_APP = 5,
    SP_RT_APP = 6,
    SP_RESTRICTED = 7,
    // PICO OS 5.13.7 cpuset policies (ProcessSmtEx.THREAD_GROUP_*); the cpusets are created by
    // the vendor init.picovr.rc. Only set_cpuset_policy() distinguishes them.
    SP_CLUSTER_BIG = 8,      // PicoSystemCapacity: cpuset pico-system
    SP_CLUSTER_SUPER = 9,    // ClusterSuperCapacity: cpuset cluster-super
    SP_DEX2OAT = 10,         // Dex2oatCapacity: cpuset dex2oat
    SP_APP_INSHELL = 11,     // PicoInShellCapacity: cpuset app-inshell
    SP_SHELL_APP = 12,       // PicoShellAppCapacity: cpuset shell-app
    SP_VRFOREGROUND = 13,    // PicoVrForegroundCapacity: cpuset vrforeground
    SP_COMPOSITOR = 14,      // CompositorCapacity: cpuset compositor
    SP_CNT,
    SP_MAX = SP_CNT - 1,
    SP_SYSTEM_DEFAULT = SP_FOREGROUND,
} SchedPolicy;

extern int set_cpuset_policy(int tid, SchedPolicy policy);

/* Smartisan cgroup freezer: moves thread tid into the freezer cgroup (task profile
 * ApplicationFreezeOn) for SP_FREEZE and back to the root freezer cgroup (ApplicationFreezeOff)
 * for any other policy. Zero tid means current thread.
 * Return value: 0 for success, or -1 for error.
 */
extern int set_freeze_policy(int tid, SchedPolicy policy);

/* Assign thread tid to the cgroup associated with the specified policy.
 * If the thread is a thread group leader, that is it's gettid() == getpid(),
 * then the other threads in the same thread group are _not_ affected.
 * On platforms which support gettid(), zero tid means current thread.
 * Return value: 0 for success, or -errno for error.
 */
extern int set_sched_policy(int tid, SchedPolicy policy);

/* Return the policy associated with the cgroup of thread tid via policy pointer.
 * On platforms which support gettid(), zero tid means current thread.
 * Return value: 0 for success, or -1 for error and set errno.
 */
extern int get_sched_policy(int tid, SchedPolicy* policy);

/* Return a displayable string corresponding to policy.
 * Return value: non-NULL NUL-terminated name of unspecified length;
 * the caller is responsible for displaying the useful part of the string.
 */
extern const char* get_sched_policy_name(SchedPolicy policy);

#ifdef __cplusplus
}
#endif
