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

// Smartisan meminfo dumps, ported from the factory PICO OS 5.13.7 libmeminfo_utils.so
// (built there from this path, system/core/libcutils/sysmeminfo_utils.cpp).

#include <meminfo_utils/sysmeminfo_utils.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <meminfo/procmeminfo.h>
#include <meminfo/sysmeminfo.h>
#include <memtrack/memtrack.h>

namespace android {
namespace meminfo_utils {

// Heap indices of android_os_Debug.cpp.
enum {
    HEAP_UNKNOWN,
    HEAP_DALVIK,
    HEAP_NATIVE,

    HEAP_DALVIK_OTHER,
    HEAP_STACK,
    HEAP_CURSOR,
    HEAP_ASHMEM,
    HEAP_GL_DEV,
    HEAP_UNKNOWN_DEV,
    HEAP_SO,
    HEAP_JAR,
    HEAP_APK,
    HEAP_TTF,
    HEAP_DEX,
    HEAP_OAT,
    HEAP_ART,
    HEAP_UNKNOWN_MAP,
    HEAP_GRAPHICS,
    HEAP_GL,
    HEAP_OTHER_MEMTRACK,

    // Dalvik extra sections (heap).
    HEAP_DALVIK_NORMAL,
    HEAP_DALVIK_LARGE,
    HEAP_DALVIK_ZYGOTE,
    HEAP_DALVIK_NON_MOVING,

    // Dalvik other extra sections.
    HEAP_DALVIK_OTHER_LINEARALLOC,
    HEAP_DALVIK_OTHER_ACCOUNTING,
    HEAP_DALVIK_OTHER_CODE_CACHE,
    HEAP_DALVIK_OTHER_COMPILER_METADATA,
    HEAP_DALVIK_OTHER_INDIRECT_REFERENCE_TABLE,

    // Boot vdex / app dex / app vdex
    HEAP_DEX_BOOT_VDEX,
    HEAP_DEX_APP_DEX,
    HEAP_DEX_APP_VDEX,

    // App art, boot art.
    HEAP_ART_APP,
    HEAP_ART_BOOT,

    _NUM_HEAP,
    _NUM_EXCLUSIVE_HEAP = HEAP_OTHER_MEMTRACK + 1,
    _NUM_CORE_HEAP = HEAP_NATIVE + 1
};

static std::string heap_names[_NUM_EXCLUSIVE_HEAP] = {
        "HEAP_UNKNOWN:", "Dalvik Heap:", "Native Heap:", "Dalvik Other:", "Stack:",
        "Cursor:",       "Ashmem:",      "Gfx dev:",     "Other dev:",    ".so mmap:",
        ".jar mmap:",    ".apk mmap:",   ".ttf mmap:",   ".dex mmap:",    ".oat mmap:",
        ".art mmap:",    "Other mmap:",  "EGL mtrack:",  "GL mtrack:",    "Other mtrack:",
};

static const char* const meminfo_tags[] = {
        "MemTotal:",   "MemFree:",     "Buffers:",    "Cached:",      "Shmem:",
        "Slab:",       "SReclaimable:", "SUnreclaim:", "SwapTotal:",   "SwapFree:",
        "ZRam:",       "Mapped:",      "VmallocUsed:", "PageTables:", "KernelStack:",
        "GFX_cached:", "MemAvailable:", NULL,
};
static const int meminfo_tags_len[] = {
        9, 8, 8, 7, 6, 5, 13, 11, 10, 9, 5, 7, 12, 11, 12, 11, 13, 0,
};
static constexpr size_t kMemInfoTagCount = arraysize(meminfo_tags) - 1;

// A process whose smaps_rollup Pss + SwapPss + memtrack total (kB) exceeds this is dumped in
// detail: 800 MiB for processes with a negative oom_score_adj, 2408 MiB for the others.
static constexpr int kImportantNativePssKb = 819200;
static constexpr int kImportantAppPssKb = 2465792;

bool SysMemInfo_utils::GetMemInfoFast(long* mem, const std::string& path) {
    char buffer[2048];

    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        PLOG(ERROR) << "Unable to open /proc/meminfo:" << strerror(errno);
        return false;
    }

    int len = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);

    if (len < 0) {
        PLOG(ERROR) << "Empty /proc/meminfo";
        return false;
    }
    buffer[len] = 0;

    size_t numFound = 0;
    char* p = buffer;
    while (*p && numFound < arraysize(meminfo_tags_len)) {
        for (size_t i = 0; meminfo_tags[i]; i++) {
            if (strncmp(p, meminfo_tags[i], meminfo_tags_len[i]) == 0) {
                p += meminfo_tags_len[i];
                while (*p == ' ') p++;
                char* num = p;
                while (*p >= '0' && *p <= '9') p++;
                if (*p != 0) {
                    *p = 0;
                    p++;
                }
                mem[i] = atoll(num);
                numFound++;
                break;
            }
        }
        while (*p && *p != '\n') {
            p++;
        }
        if (*p) p++;
    }

    return true;
}

bool SysMemInfo_utils::GetProcsIonHeap(std::vector<std::string>* out,
                                       std::map<int, int>* ion_map) {
    char line[100] = {0};
    FILE* fp = popen("cat /d/dma_buf/dmaprocs", "r");
    if (fp == NULL) {
        LOG(ERROR) << "Unable to open /d/dma_buf/dmaprocs";
        return false;
    }

    std::smatch match;
    std::regex pid_pattern("PID +[0-9]{1,10}");
    std::regex size_pattern("size: +[0-9]{1,20}");

    out->push_back("ION Info:");
    for (memset(line, 0, sizeof(line)); fgets(line, sizeof(line) - 1, fp) != NULL;
         memset(line, 0, sizeof(line))) {
        char pid[32] = {0};
        char ion_line[128] = {0};
        char size[64] = {0};
        std::string str(line);

        if (!std::regex_search(str, match, pid_pattern)) {
            continue;
        }
        // "PID <pid>"
        memcpy(pid, match.str(0).c_str() + 4, strlen(match.str(0).c_str()) - 4);

        if (!std::regex_search(str, match, size_pattern)) {
            continue;
        }
        // "size: <size>"
        memcpy(size, match.str(0).c_str() + 6, strlen(match.str(0).c_str()) - 6);

        char cmdline_path[128] = {0};
        char cmdline[128] = {0};
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", pid);
        read_with_default(cmdline_path, cmdline, sizeof(cmdline), "<unknown>");

        int ion_heap_other = atoi(size) > (*ion_map)[atoi(pid)]
                                     ? atoi(size) - (*ion_map)[atoi(pid)]
                                     : 0;
        snprintf(ion_line, sizeof(ion_line) - 1, "pid: %s\tion_heap_other: %-8d\tname: %s", pid,
                 ion_heap_other, cmdline);
        out->push_back(std::string(ion_line));
    }
    pclose(fp);

    return true;
}

void read_with_default(const char* path, char* buf, size_t len, const char* default_value) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        int rc = TEMP_FAILURE_RETRY(read(fd, buf, len - 1));
        if (rc != -1) {
            buf[rc] = '\0';

            // Trim trailing newlines.
            if (rc > 0 && buf[rc - 1] == '\n') {
                buf[rc - 1] = '\0';
            }
            close(fd);
            return;
        }
        close(fd);
    }
    strcpy(buf, default_value);
}

bool SysMemInfo_utils::cmp(const std::pair<std::string, int>& a,
                           const std::pair<std::string, int>& b) {
    return a.second > b.second;
}

bool SysMemInfo_utils::GetAllProcsMeminfoFast(std::vector<std::string>* out) {
    std::map<int, int> ion_map;
    std::vector<std::string> pids;

    LOG(WARNING) << "start to dump all process memory.";
    DIR* dir = opendir("/proc");
    if (dir == NULL) {
        LOG(ERROR) << "open proc node failed.";
        return false;
    }

    out->push_back("PSS Top 20 Process Meminfo:");
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0 && isdigit(entry->d_name[0])) {
            pids.push_back(std::string(entry->d_name));
        }
    }
    closedir(dir);

    if (!GetProcsMeminfoFast(out, &pids, &ion_map)) {
        LOG(ERROR) << "GetProcsMeminfoFast failed.";
        return false;
    }

    if (!GetProcsIonHeap(out, &ion_map)) {
        LOG(ERROR) << "GetProcsIonHeap failed.";
        return false;
    }

    for (std::string line : *out) {
        LOG(WARNING) << line;
    }

    return true;
}

bool SysMemInfo_utils::GetProcsMeminfoFast(std::vector<std::string>* out,
                                           std::vector<std::string>* pids,
                                           std::map<int, int>* ion_map) {
    if (pids->empty()) {
        return false;
    }

    std::vector<std::pair<std::string, int>> procs;
    std::map<std::string, std::string> proc_lines;
    std::vector<int> important_pids;

    for (auto it = pids->begin(); it != pids->end(); ++it) {
        std::string pid = *it;

        char cmdline_path[128] = {0};
        char cmdline[128] = {0};
        char path[64] = {0};
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", pid.c_str());
        read_with_default(cmdline_path, cmdline, sizeof(cmdline), "<unknown>");

        snprintf(path, sizeof(path) - 1, "/proc/%s/oom_score_adj", pid.c_str());
        int fd = open(path, O_RDONLY);
        char oom_score_adj[64] = {0};
        int len = read(fd, oom_score_adj, sizeof(oom_score_adj) - 1);
        close(fd);
        if (len < 0) {
            continue;
        }
        char* endptr = NULL;
        int oom_adj = strtoull(oom_score_adj, &endptr, 10);

        snprintf(path, sizeof(path) - 1, "/proc/%s/smaps_rollup", pid.c_str());
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            continue;
        }
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        len = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (len < 0) {
            continue;
        }

        int pss = 0;
        int swap_pss = 0;
        int total_pss = 0;
        char* p = buffer;
        while (*p) {
            if (strncmp(p, "Pss:", 4) == 0) {
                while (*p != ' ') p++;
                pss = strtoull(p, &endptr, 10);
                total_pss += pss;
            }
            if (strncmp(p, "SwapPss:", 8) == 0) {
                while (*p != ' ') p++;
                swap_pss = strtoull(p, &endptr, 10);
                total_pss += swap_pss;
                break;
            }
            while (*p++ != '\n')
                ;
        }

        int egl = 0;
        int gl = 0;
        int graphic_other = 0;
        graphics_memory_pss graphics_mem;
        if (read_memtrack_memory(atoi(pid.c_str()), &graphics_mem) == 0) {
            egl = graphics_mem.graphics;
            if (egl > 0) {
                (*ion_map)[atoi(pid.c_str())] = egl;
            }
            gl = graphics_mem.gl;
            graphic_other = graphics_mem.other;
        }
        int total = egl + total_pss + gl + graphic_other;

        if ((oom_adj < 0 && total > kImportantNativePssKb) ||
            (oom_adj >= 0 && total > kImportantAppPssKb)) {
            important_pids.push_back(atoi(pid.c_str()));
        }

        char line[256] = {0};
        snprintf(line, sizeof(line),
                 "pid: %s\t total_pss: %-8d\t pss: %-8d\t egl: %-8d\t gl: %-8d\t graphic_other: "
                 "%-8d\t swap_pss: %-8d\t name: %s\t",
                 pid.c_str(), total, pss, egl, gl, graphic_other, swap_pss, cmdline);
        procs.push_back(std::make_pair(pid, total));
        proc_lines[pid] = line;
    }

    std::sort(procs.begin(), procs.end(), cmp);
    for (size_t i = 0; i < procs.size() && i < 20; i++) {
        out->push_back(proc_lines[procs[i].first]);
    }

    for (int pid : important_pids) {
        stats_t stats[_NUM_HEAP];
        bool foundSwapPss;
        memset(&stats, 0, sizeof(stats));
        load_maps(pid, stats, &foundSwapPss);

        out->push_back("Important process Meminfo Detail, pid: " + std::to_string(pid));
        for (int i = 1; i < HEAP_GRAPHICS; i++) {
            char line[256] = {0};
            snprintf(line, sizeof(line), "%13s\t%8d", heap_names[i].c_str(),
                     stats[i].pss + (foundSwapPss ? stats[i].swappedOutPss : 0));
            out->push_back(std::string(line));
        }
    }

    return true;
}

/*
 * Retrieves the graphics memory that is unaccounted for in /proc/pid/smaps.
 */
int read_memtrack_memory(int pid, graphics_memory_pss* graphics_mem) {
    struct memtrack_proc* p = memtrack_proc_new();
    if (p == NULL) {
        LOG(ERROR) << "failed to create memtrack_proc";
        return -1;
    }

    int err = read_memtrack_memory(p, pid, graphics_mem);
    memtrack_proc_destroy(p);
    return err;
}

void load_maps(int pid, stats_t* stats, bool* foundSwapPss) {
    *foundSwapPss = false;
    uint64_t prev_end = 0;
    int prev_heap = HEAP_UNKNOWN;

    std::string smaps_path = base::StringPrintf("/proc/%d/smaps", pid);
    auto vma_scan = [&](const meminfo::Vma& vma) {
        int which_heap = HEAP_UNKNOWN;
        int sub_heap = HEAP_UNKNOWN;
        bool is_swappable = false;
        std::string name;
        if (base::EndsWith(vma.name, " (deleted)")) {
            name = vma.name.substr(0, vma.name.size() - strlen(" (deleted)"));
        } else {
            name = vma.name;
        }

        uint32_t namesz = name.size();
        if (base::StartsWith(name, "[heap]")) {
            which_heap = HEAP_NATIVE;
        } else if (base::StartsWith(name, "[anon:libc_malloc]")) {
            which_heap = HEAP_NATIVE;
        } else if (base::StartsWith(name, "[stack")) {
            which_heap = HEAP_STACK;
        } else if (base::EndsWith(name, ".so")) {
            which_heap = HEAP_SO;
            is_swappable = true;
        } else if (base::EndsWith(name, ".jar")) {
            which_heap = HEAP_JAR;
            is_swappable = true;
        } else if (base::EndsWith(name, ".apk")) {
            which_heap = HEAP_APK;
            is_swappable = true;
        } else if (base::EndsWith(name, ".ttf")) {
            which_heap = HEAP_TTF;
            is_swappable = true;
        } else if ((base::EndsWith(name, ".odex")) ||
                   (namesz > 4 && strstr(name.c_str(), ".dex") != nullptr)) {
            which_heap = HEAP_DEX;
            sub_heap = HEAP_DEX_APP_DEX;
            is_swappable = true;
        } else if (base::EndsWith(name, ".vdex")) {
            which_heap = HEAP_DEX;
            // Handle system@framework@boot and system/framework/boot
            if ((strstr(name.c_str(), "@boot") != nullptr) ||
                (strstr(name.c_str(), "/boot"))) {
                sub_heap = HEAP_DEX_BOOT_VDEX;
            } else {
                sub_heap = HEAP_DEX_APP_VDEX;
            }
            is_swappable = true;
        } else if (base::EndsWith(name, ".oat")) {
            which_heap = HEAP_OAT;
            is_swappable = true;
        } else if (base::EndsWith(name, ".art") || base::EndsWith(name, ".art]")) {
            which_heap = HEAP_ART;
            // Handle system@framework@boot* and system/framework/boot*
            if ((strstr(name.c_str(), "@boot") != nullptr) ||
                (strstr(name.c_str(), "/boot"))) {
                sub_heap = HEAP_ART_BOOT;
            } else {
                sub_heap = HEAP_ART_APP;
            }
            is_swappable = true;
        } else if (base::StartsWith(name, "/dev/")) {
            which_heap = HEAP_UNKNOWN_DEV;
            if (base::StartsWith(name, "/dev/kgsl-3d0")) {
                which_heap = HEAP_GL_DEV;
            } else if (base::StartsWith(name, "/dev/ashmem/CursorWindow")) {
                which_heap = HEAP_CURSOR;
            } else if (base::StartsWith(name, "/dev/ashmem")) {
                which_heap = HEAP_ASHMEM;
            }
        } else if (base::StartsWith(name, "[anon:")) {
            which_heap = HEAP_UNKNOWN;
            if (base::StartsWith(name, "[anon:dalvik-")) {
                which_heap = HEAP_DALVIK_OTHER;
                if (base::StartsWith(name, "[anon:dalvik-LinearAlloc")) {
                    sub_heap = HEAP_DALVIK_OTHER_LINEARALLOC;
                } else if (base::StartsWith(name, "[anon:dalvik-alloc space") ||
                           base::StartsWith(name, "[anon:dalvik-main space")) {
                    // This is the regular Dalvik heap.
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_NORMAL;
                } else if (base::StartsWith(name, "[anon:dalvik-large object space") ||
                           base::StartsWith(name, "[anon:dalvik-free list large object space")) {
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_LARGE;
                } else if (base::StartsWith(name, "[anon:dalvik-non moving space")) {
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_NON_MOVING;
                } else if (base::StartsWith(name, "[anon:dalvik-zygote space")) {
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_ZYGOTE;
                } else if (base::StartsWith(name, "[anon:dalvik-indirect ref")) {
                    sub_heap = HEAP_DALVIK_OTHER_INDIRECT_REFERENCE_TABLE;
                } else if (base::StartsWith(name, "[anon:dalvik-jit-code-cache") ||
                           base::StartsWith(name, "[anon:dalvik-data-code-cache")) {
                    sub_heap = HEAP_DALVIK_OTHER_CODE_CACHE;
                } else if (base::StartsWith(name, "[anon:dalvik-CompilerMetadata")) {
                    sub_heap = HEAP_DALVIK_OTHER_COMPILER_METADATA;
                } else {
                    sub_heap = HEAP_DALVIK_OTHER_ACCOUNTING;  // Default to accounting.
                }
            }
        } else if (namesz > 0) {
            which_heap = HEAP_UNKNOWN_MAP;
        } else if (vma.start == prev_end && prev_heap == HEAP_SO) {
            // bss section of a shared library
            which_heap = HEAP_SO;
        }

        prev_end = vma.end;
        prev_heap = which_heap;

        const meminfo::MemUsage& usage = vma.usage;
        if (usage.swap_pss > 0 && *foundSwapPss != true) {
            *foundSwapPss = true;
        }

        uint64_t swapable_pss = 0;
        if (is_swappable && (usage.pss > 0)) {
            float sharing_proportion = 0.0;
            if ((usage.shared_clean > 0) || (usage.shared_dirty > 0)) {
                sharing_proportion =
                        (usage.pss - usage.uss) / (usage.shared_clean + usage.shared_dirty);
            }
            swapable_pss = (sharing_proportion * usage.shared_clean) + usage.private_clean;
        }

        stats[which_heap].pss += usage.pss;
        stats[which_heap].swappablePss += swapable_pss;
        stats[which_heap].rss += usage.rss;
        stats[which_heap].privateDirty += usage.private_dirty;
        stats[which_heap].sharedDirty += usage.shared_dirty;
        stats[which_heap].privateClean += usage.private_clean;
        stats[which_heap].sharedClean += usage.shared_clean;
        stats[which_heap].swappedOut += usage.swap;
        stats[which_heap].swappedOutPss += usage.swap_pss;
        if (which_heap == HEAP_DALVIK || which_heap == HEAP_DALVIK_OTHER ||
            which_heap == HEAP_DEX || which_heap == HEAP_ART) {
            stats[sub_heap].pss += usage.pss;
            stats[sub_heap].swappablePss += swapable_pss;
            stats[sub_heap].rss += usage.rss;
            stats[sub_heap].privateDirty += usage.private_dirty;
            stats[sub_heap].sharedDirty += usage.shared_dirty;
            stats[sub_heap].privateClean += usage.private_clean;
            stats[sub_heap].sharedClean += usage.shared_clean;
            stats[sub_heap].swappedOut += usage.swap;
            stats[sub_heap].swappedOutPss += usage.swap_pss;
        }
    };

    meminfo::ForEachVmaFromFile(smaps_path, vma_scan);
}

bool SysMemInfo_utils::GetAllMeminfoFast(std::vector<std::string>* out, int pid) {
    long mem[kMemInfoTagCount] = {0};
    GetMemInfoFast(mem, "/proc/meminfo");

    uint64_t ion_heaps_kb = 0;
    meminfo::ReadIonHeapsSizeKb(&ion_heaps_kb, "/sys/kernel/ion/total_heaps_kb");
    std::string ion_heap = "IonHeap:";
    out->push_back(ion_heap + std::to_string(ion_heaps_kb) + " kb");

    bool foundSwapPss;
    stats_t stats[_NUM_HEAP];
    memset(&stats, 0, sizeof(stats));
    load_maps(pid, stats, &foundSwapPss);

    graphics_memory_pss graphics_mem;
    if (read_memtrack_memory(pid, &graphics_mem) == 0) {
        stats[HEAP_GRAPHICS].pss = graphics_mem.graphics;
        stats[HEAP_GRAPHICS].privateDirty = graphics_mem.graphics;
        stats[HEAP_GRAPHICS].rss = graphics_mem.graphics;
        stats[HEAP_GL].pss = graphics_mem.gl;
        stats[HEAP_GL].privateDirty = graphics_mem.gl;
        stats[HEAP_GL].rss = graphics_mem.gl;
        stats[HEAP_OTHER_MEMTRACK].pss = graphics_mem.other;
        stats[HEAP_OTHER_MEMTRACK].privateDirty = graphics_mem.other;
        stats[HEAP_OTHER_MEMTRACK].rss = graphics_mem.other;
    }

    for (int i = _NUM_CORE_HEAP; i < _NUM_EXCLUSIVE_HEAP; i++) {
        stats[HEAP_UNKNOWN].pss += stats[i].pss;
        stats[HEAP_UNKNOWN].swappablePss += stats[i].swappablePss;
        stats[HEAP_UNKNOWN].rss += stats[i].rss;
        stats[HEAP_UNKNOWN].privateDirty += stats[i].privateDirty;
        stats[HEAP_UNKNOWN].sharedDirty += stats[i].sharedDirty;
        stats[HEAP_UNKNOWN].privateClean += stats[i].privateClean;
        stats[HEAP_UNKNOWN].sharedClean += stats[i].sharedClean;
        stats[HEAP_UNKNOWN].swappedOut += stats[i].swappedOut;
        stats[HEAP_UNKNOWN].swappedOutPss += stats[i].swappedOutPss;
    }

    for (size_t i = 0; i < kMemInfoTagCount; i++) {
        out->push_back(meminfo_tags[i] + std::to_string(mem[i]) + " kb");
    }

    out->push_back("Current process pss detail as follows:");
    int total = 0;
    for (int i = 1; i < HEAP_OTHER_MEMTRACK; i++) {
        out->push_back(heap_names[i] + std::to_string(stats[i].pss) + " kb, " +
                       (foundSwapPss ? "SwapPss:" + std::to_string(stats[i].swappedOutPss) + " kb"
                                     : "Swap:" + std::to_string(stats[i].swappedOut) + " kb"));
        total += stats[i].pss + (foundSwapPss ? stats[i].swappedOutPss : stats[i].swappedOut);
    }
    out->push_back("Total:" + std::to_string(total) + " kb");

    return true;
}

/*
 * Uses libmemtrack to retrieve graphics memory that the process is using.
 * Any graphics memory reported in /proc/pid/smaps is not included here.
 */
int read_memtrack_memory(struct memtrack_proc* p, int pid, graphics_memory_pss* graphics_mem) {
    int err = memtrack_proc_get(p, pid);
    if (err != 0) {
        LOG(ERROR) << "failed to get memory consumption info: " << err;
        return err;
    }

    ssize_t pss = memtrack_proc_graphics_pss(p);
    if (pss < 0) {
        LOG(ERROR) << "failed to get graphics pss: " << pss;
        return pss;
    }
    graphics_mem->graphics = pss / 1024;

    pss = memtrack_proc_gl_pss(p);
    if (pss < 0) {
        LOG(ERROR) << "failed to get gl pss: " << pss;
        return pss;
    }
    graphics_mem->gl = pss / 1024;

    pss = memtrack_proc_other_pss(p);
    if (pss < 0) {
        LOG(ERROR) << "failed to get other pss: " << pss;
        return pss;
    }
    graphics_mem->other = pss / 1024;

    return 0;
}

}  // namespace meminfo_utils
}  // namespace android
