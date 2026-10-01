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

// Smartisan "meminfo fast" dumps of the factory PICO OS 5.13.7 libmeminfo_utils.so
// (source system/core/libcutils/sysmeminfo_utils.cpp): text lines describing the system and
// per-process memory (smaps_rollup Pss/SwapPss, memtrack, ION) for logging, used by
// Debug.getAllProcsMeminfoFast() in libandroid_runtime and by crash_dump.

#include <stddef.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

struct memtrack_proc;

namespace android {
namespace meminfo_utils {

// Container used to retrieve graphics memory pss (kB).
struct graphics_memory_pss {
    int graphics;
    int gl;
    int other;
};

// Per-heap smaps totals (kB), as in android_os_Debug.cpp.
struct stats_t {
    int pss;
    int swappablePss;
    int rss;
    int privateDirty;
    int sharedDirty;
    int privateClean;
    int sharedClean;
    int swappedOut;
    int swappedOutPss;
};

class SysMemInfo_utils {
  public:
    // Parses the /proc/meminfo format file path into mem[0..16] (kB, in the order MemTotal,
    // MemFree, Buffers, Cached, Shmem, Slab, SReclaimable, SUnreclaim, SwapTotal, SwapFree,
    // ZRam, Mapped, VmallocUsed, PageTables, KernelStack, GFX_cached, MemAvailable).
    bool GetMemInfoFast(long* mem, const std::string& path);
    // Appends "ION Info:" and one line per /d/dma_buf/dmaprocs process (dma-buf size beyond
    // the EGL memtrack size recorded in ion_map).
    bool GetProcsIonHeap(std::vector<std::string>* out, std::map<int, int>* ion_map);
    // Appends the 20 processes of pids with the largest smaps_rollup Pss + SwapPss + memtrack
    // and the heap details of the processes above the importance thresholds; records each
    // process' EGL memtrack size in ion_map.
    bool GetProcsMeminfoFast(std::vector<std::string>* out, std::vector<std::string>* pids,
                             std::map<int, int>* ion_map);
    // GetProcsMeminfoFast() and GetProcsIonHeap() for every process in /proc; the lines are
    // also logged.
    bool GetAllProcsMeminfoFast(std::vector<std::string>* out);
    // System meminfo, ION heaps and the smaps/memtrack heap details of pid.
    bool GetAllMeminfoFast(std::vector<std::string>* out, int pid);

    static bool cmp(const std::pair<std::string, int>& a, const std::pair<std::string, int>& b);
};

void read_with_default(const char* path, char* buf, size_t len, const char* default_value);
int read_memtrack_memory(struct memtrack_proc* p, int pid, graphics_memory_pss* graphics_mem);
int read_memtrack_memory(int pid, graphics_memory_pss* graphics_mem);
void load_maps(int pid, stats_t* stats, bool* foundSwapPss);

}  // namespace meminfo_utils
}  // namespace android
