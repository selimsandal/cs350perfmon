#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <fstream>
#include <memory>
#include <atomic>
#include <mutex>
#include <string>
#include <sstream>
#include <cstdlib>
#include <map>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <cmath>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <pdh.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef PDH_CSTATUS_VALID_DATA
#define PDH_CSTATUS_VALID_DATA 0x00000000L
#endif
#ifndef PDH_INVALID_DATA
#define PDH_INVALID_DATA 0xC0000BF6L
#endif

#elif __APPLE__
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach/processor_info.h>
#include <mach/thread_info.h>
#include <mach/task_info.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <libproc.h>
#elif __linux__
#include <unistd.h>
#include <sys/times.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#elif __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <kvm.h>
#endif

// Cross-platform high-resolution timer
class Timer {
private:
#ifdef _WIN32
    LARGE_INTEGER frequency;
    LARGE_INTEGER start_time;
#else
    std::chrono::high_resolution_clock::time_point start_time;
#endif

public:
    Timer() {
#ifdef _WIN32
        QueryPerformanceFrequency(&frequency);
#endif
        reset();
    }

    void reset() {
#ifdef _WIN32
        QueryPerformanceCounter(&start_time);
#else
        start_time = std::chrono::high_resolution_clock::now();
#endif
    }

    double elapsed_ms() {
#ifdef _WIN32
        LARGE_INTEGER current;
        QueryPerformanceCounter(&current);
        return ((double)(current.QuadPart - start_time.QuadPart) * 1000.0) / frequency.QuadPart;
#else
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(now - start_time).count();
#endif
    }

    uint64_t elapsed_ns() {
#ifdef _WIN32
        LARGE_INTEGER current;
        QueryPerformanceCounter(&current);
        return ((uint64_t)(current.QuadPart - start_time.QuadPart) * 1000000000ULL) / frequency.QuadPart;
#else
        auto now = std::chrono::high_resolution_clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now - start_time).count();
#endif
    }
};

// Per-core CPU statistics
struct CoreStats {
    uint32_t core_id;
    double usage_percent;
    double user_percent;
    double system_percent;
    double idle_percent;
    double iowait_percent;
    uint64_t interrupts;
    uint64_t context_switches;
    uint64_t cache_misses;
    double frequency_mhz;
};

// Process scheduling information
struct ProcessInfo {
    uint32_t pid;
    uint32_t ppid;
    uint32_t tid;
    std::string name;
    uint32_t priority;
    uint32_t nice_value;
    std::string state;
    uint32_t cpu_affinity;
    uint32_t current_cpu;
    uint64_t voluntary_context_switches;
    uint64_t involuntary_context_switches;
    double cpu_time_ms;
    uint64_t memory_rss;
    uint64_t memory_vms;
    uint64_t page_faults;
    uint64_t minor_faults;
    uint64_t major_faults;
    double scheduler_latency_ns;
    bool is_realtime;
    uint32_t scheduler_policy;
};

// Run queue and scheduler statistics
struct SchedulerStats {
    std::vector<uint32_t> runqueue_lengths;  // Per-CPU runqueue lengths
    uint32_t total_runnable_tasks;
    uint32_t total_blocked_tasks;
    uint32_t total_sleeping_tasks;
    double avg_load_1min;
    double avg_load_5min;
    double avg_load_15min;
    uint64_t total_context_switches;
    uint64_t voluntary_context_switches;
    uint64_t involuntary_context_switches;
    double avg_scheduler_latency_ns;
    double max_scheduler_latency_ns;
    uint32_t realtime_processes;
    uint32_t normal_processes;
    std::vector<uint32_t> priority_distribution;  // Count of processes per priority level
};

// System-wide metrics for scheduler evaluation
struct SystemMetrics {
    std::chrono::system_clock::time_point timestamp;

    // CPU and Core Information
    std::vector<CoreStats> per_core_stats;
    double overall_cpu_usage;
    double overall_system_usage;
    double overall_user_usage;
    double overall_iowait;

    // Memory and System Load
    double memory_usage_percent;
    uint64_t memory_available_kb;
    uint64_t memory_total_kb;
    uint64_t swap_usage_kb;
    uint64_t swap_total_kb;

    // Scheduler-specific metrics
    SchedulerStats scheduler_stats;
    std::vector<ProcessInfo> top_processes;  // Top CPU/memory consumers

    // Latency and Responsiveness
    double min_response_time_ms;
    double avg_response_time_ms;
    double max_response_time_ms;
    double p95_response_time_ms;
    double p99_response_time_ms;

    // System Stress Indicators
    uint64_t page_faults;
    uint64_t cache_misses;
    uint64_t tlb_misses;
    uint32_t active_threads;
    uint32_t total_processes;

    // Performance counters
    uint64_t instructions_retired;
    uint64_t cycles_elapsed;
    double instructions_per_cycle;
};

// Base class for platform-specific monitoring
class SystemMonitor {
public:
    virtual ~SystemMonitor() = default;
    virtual bool initialize() = 0;
    virtual SystemMetrics collect_metrics() = 0;
    virtual void cleanup() = 0;
    virtual uint32_t get_cpu_count() = 0;
};

#ifdef _WIN32
class WindowsMonitor : public SystemMonitor {
private:
    PDH_HQUERY query;
    std::vector<PDH_HCOUNTER> cpu_counters;
    std::vector<PDH_HCOUNTER> cpu_user_counters;
    std::vector<PDH_HCOUNTER> cpu_system_counters;
    PDH_HCOUNTER memory_available_counter;
    PDH_HCOUNTER context_switch_counter;
    PDH_HCOUNTER interrupt_counter;
    PDH_HCOUNTER process_counter;
    PDH_HCOUNTER thread_counter;
    bool first_sample;
    uint32_t cpu_count;
    std::map<uint32_t, ProcessInfo> prev_process_info;

public:
    WindowsMonitor() : query(NULL), first_sample(true), cpu_count(0) {}

    uint32_t get_cpu_count() override {
        if (cpu_count == 0) {
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            cpu_count = sys_info.dwNumberOfProcessors;
        }
        return cpu_count;
    }

    bool initialize() override {
        PDH_STATUS status = PdhOpenQueryW(NULL, 0, &query);
        if (status != ERROR_SUCCESS) return false;

        cpu_count = get_cpu_count();
        cpu_counters.resize(cpu_count);
        cpu_user_counters.resize(cpu_count);
        cpu_system_counters.resize(cpu_count);

        // Add per-CPU counters
        for (uint32_t i = 0; i < cpu_count; i++) {
            std::wstring cpu_path = L"\\Processor(" + std::to_wstring(i) + L")\\% Processor Time";
            std::wstring user_path = L"\\Processor(" + std::to_wstring(i) + L")\\% User Time";
            std::wstring system_path = L"\\Processor(" + std::to_wstring(i) + L")\\% Privileged Time";

            PdhAddCounterW(query, cpu_path.c_str(), 0, &cpu_counters[i]);
            PdhAddCounterW(query, user_path.c_str(), 0, &cpu_user_counters[i]);
            PdhAddCounterW(query, system_path.c_str(), 0, &cpu_system_counters[i]);
        }

        // System-wide counters
        PdhAddCounterW(query, L"\\Memory\\Available Bytes", 0, &memory_available_counter);
        PdhAddCounterW(query, L"\\System\\Context Switches/sec", 0, &context_switch_counter);
        PdhAddCounterW(query, L"\\Processor(_Total)\\Interrupts/sec", 0, &interrupt_counter);
        PdhAddCounterW(query, L"\\System\\Processes", 0, &process_counter);
        PdhAddCounterW(query, L"\\System\\Threads", 0, &thread_counter);

        // Initial samples
        PdhCollectQueryData(query);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        PdhCollectQueryData(query);

        return true;
    }

    std::vector<ProcessInfo> collect_process_info() {
        std::vector<ProcessInfo> processes;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return processes;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                ProcessInfo info = {};
                info.pid = pe32.th32ProcessID;
                info.ppid = pe32.th32ParentProcessID;
                info.name = std::string(pe32.szExeFile);

                // Get additional process information
                HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (process_handle) {
                    // Priority class
                    DWORD priority_class = GetPriorityClass(process_handle);
                    switch (priority_class) {
                        case REALTIME_PRIORITY_CLASS: info.priority = 24; info.is_realtime = true; break;
                        case HIGH_PRIORITY_CLASS: info.priority = 13; break;
                        case ABOVE_NORMAL_PRIORITY_CLASS: info.priority = 10; break;
                        case NORMAL_PRIORITY_CLASS: info.priority = 8; break;
                        case BELOW_NORMAL_PRIORITY_CLASS: info.priority = 6; break;
                        case IDLE_PRIORITY_CLASS: info.priority = 4; break;
                        default: info.priority = 8; break;
                    }

                    // Memory information
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(process_handle, &pmc, sizeof(pmc))) {
                        info.memory_rss = pmc.WorkingSetSize;
                        info.memory_vms = pmc.PagefileUsage;
                        info.page_faults = pmc.PageFaultCount;
                    }

                    // CPU times
                    FILETIME creation_time, exit_time, kernel_time, user_time;
                    if (GetProcessTimes(process_handle, &creation_time, &exit_time, &kernel_time, &user_time)) {
                        ULARGE_INTEGER kernel_li, user_li;
                        kernel_li.LowPart = kernel_time.dwLowDateTime;
                        kernel_li.HighPart = kernel_time.dwHighDateTime;
                        user_li.LowPart = user_time.dwLowDateTime;
                        user_li.HighPart = user_time.dwHighDateTime;

                        info.cpu_time_ms = (kernel_li.QuadPart + user_li.QuadPart) / 10000.0;
                    }

                    CloseHandle(process_handle);
                }

                processes.push_back(info);
            } while (Process32Next(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return processes;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        PdhCollectQueryData(query);

        // Per-core CPU statistics
        metrics.per_core_stats.resize(cpu_count);
        double total_cpu = 0;

        for (uint32_t i = 0; i < cpu_count; i++) {
            PDH_FMT_COUNTERVALUE counter_value;

            metrics.per_core_stats[i].core_id = i;

            // CPU usage
            if (PdhGetFormattedCounterValue(cpu_counters[i], PDH_FMT_DOUBLE, NULL, &counter_value) == ERROR_SUCCESS) {
                metrics.per_core_stats[i].usage_percent = counter_value.doubleValue;
                total_cpu += counter_value.doubleValue;
            }

            // User time
            if (PdhGetFormattedCounterValue(cpu_user_counters[i], PDH_FMT_DOUBLE, NULL, &counter_value) == ERROR_SUCCESS) {
                metrics.per_core_stats[i].user_percent = counter_value.doubleValue;
            }

            // System time
            if (PdhGetFormattedCounterValue(cpu_system_counters[i], PDH_FMT_DOUBLE, NULL, &counter_value) == ERROR_SUCCESS) {
                metrics.per_core_stats[i].system_percent = counter_value.doubleValue;
            }

            metrics.per_core_stats[i].idle_percent = 100.0 - metrics.per_core_stats[i].usage_percent;
        }

        metrics.overall_cpu_usage = total_cpu / cpu_count;

        // Memory information
        MEMORYSTATUSEX mem_status;
        mem_status.dwLength = sizeof(mem_status);
        if (GlobalMemoryStatusEx(&mem_status)) {
            metrics.memory_total_kb = mem_status.ullTotalPhys / 1024;
            metrics.memory_available_kb = mem_status.ullAvailPhys / 1024;
            metrics.memory_usage_percent = ((double)(mem_status.ullTotalPhys - mem_status.ullAvailPhys) / mem_status.ullTotalPhys) * 100.0;
            metrics.swap_total_kb = mem_status.ullTotalPageFile / 1024;
            metrics.swap_usage_kb = (mem_status.ullTotalPageFile - mem_status.ullAvailPageFile) / 1024;
        }

        // System counters
        PDH_FMT_COUNTERVALUE counter_value;
        if (PdhGetFormattedCounterValue(context_switch_counter, PDH_FMT_LARGE, NULL, &counter_value) == ERROR_SUCCESS) {
            metrics.scheduler_stats.total_context_switches = counter_value.largeValue;
        }

        if (PdhGetFormattedCounterValue(process_counter, PDH_FMT_LONG, NULL, &counter_value) == ERROR_SUCCESS) {
            metrics.total_processes = counter_value.longValue;
        }

        if (PdhGetFormattedCounterValue(thread_counter, PDH_FMT_LONG, NULL, &counter_value) == ERROR_SUCCESS) {
            metrics.active_threads = counter_value.longValue;
        }

        // Process information
        metrics.top_processes = collect_process_info();

        // Sort by CPU usage and keep top 20
        std::sort(metrics.top_processes.begin(), metrics.top_processes.end(),
                  [](const ProcessInfo& a, const ProcessInfo& b) {
                      return a.cpu_time_ms > b.cpu_time_ms;
                  });

        if (metrics.top_processes.size() > 20) {
            metrics.top_processes.resize(20);
        }

        // Load average simulation (Windows doesn't have native load average)
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        metrics.scheduler_stats.avg_load_1min = (metrics.overall_cpu_usage / 100.0) * sys_info.dwNumberOfProcessors;

        first_sample = false;
        return metrics;
    }

    void cleanup() override {
        if (query) {
            PdhCloseQuery(query);
            query = NULL;
        }
    }
};

#elif __APPLE__
class MacOSMonitor : public SystemMonitor {
private:
    uint32_t cpu_count;
    std::vector<processor_cpu_load_info_data_t> prev_cpu_info;
    bool first_sample;

public:
    MacOSMonitor() : cpu_count(0), first_sample(true) {}

    uint32_t get_cpu_count() override {
        if (cpu_count == 0) {
            size_t size = sizeof(cpu_count);
            sysctlbyname("hw.logicalcpu", &cpu_count, &size, NULL, 0);
        }
        return cpu_count;
    }

    bool initialize() override {
        cpu_count = get_cpu_count();
        prev_cpu_info.resize(cpu_count);

        // Get initial CPU sample
        processor_cpu_load_info_data_t *cpu_info;
        mach_msg_type_number_t cpu_info_count;

        if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO,
                               &cpu_count, (processor_info_array_t*)&cpu_info,
                               &cpu_info_count) == KERN_SUCCESS) {
            for (uint32_t i = 0; i < cpu_count; i++) {
                prev_cpu_info[i] = cpu_info[i];
            }
            vm_deallocate(mach_task_self(), (vm_address_t)cpu_info, cpu_info_count);
        }

        return true;
    }

    std::vector<ProcessInfo> collect_process_info() {
        std::vector<ProcessInfo> processes;

        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        size_t size;

        if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) return processes;

        std::vector<kinfo_proc> proc_list(size / sizeof(kinfo_proc));
        if (sysctl(mib, 4, proc_list.data(), &size, NULL, 0) < 0) return processes;

        int proc_count = size / sizeof(kinfo_proc);

        for (int i = 0; i < proc_count; i++) {
            ProcessInfo info = {};
            info.pid = proc_list[i].kp_proc.p_pid;
            info.ppid = proc_list[i].kp_eproc.e_ppid;
            info.name = std::string(proc_list[i].kp_proc.p_comm);
            info.priority = proc_list[i].kp_proc.p_priority;
            info.nice_value = proc_list[i].kp_proc.p_nice;

            // Process state
            switch (proc_list[i].kp_proc.p_stat) {
                case SRUN: info.state = "running"; break;
                case SSLEEP: info.state = "sleeping"; break;
                case SSTOP: info.state = "stopped"; break;
                case SZOMB: info.state = "zombie"; break;
                default: info.state = "unknown"; break;
            }

            processes.push_back(info);
        }

        return processes;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // Per-core CPU statistics
        processor_cpu_load_info_data_t *cpu_info;
        mach_msg_type_number_t cpu_info_count;

        if (host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO,
                               &cpu_count, (processor_info_array_t*)&cpu_info,
                               &cpu_info_count) == KERN_SUCCESS) {

            metrics.per_core_stats.resize(cpu_count);
            double total_usage = 0;

            for (uint32_t i = 0; i < cpu_count; i++) {
                metrics.per_core_stats[i].core_id = i;

                if (!first_sample) {
                    uint64_t user_diff = cpu_info[i].cpu_ticks[CPU_STATE_USER] - prev_cpu_info[i].cpu_ticks[CPU_STATE_USER];
                    uint64_t sys_diff = cpu_info[i].cpu_ticks[CPU_STATE_SYSTEM] - prev_cpu_info[i].cpu_ticks[CPU_STATE_SYSTEM];
                    uint64_t idle_diff = cpu_info[i].cpu_ticks[CPU_STATE_IDLE] - prev_cpu_info[i].cpu_ticks[CPU_STATE_IDLE];
                    uint64_t nice_diff = cpu_info[i].cpu_ticks[CPU_STATE_NICE] - prev_cpu_info[i].cpu_ticks[CPU_STATE_NICE];

                    uint64_t total_diff = user_diff + sys_diff + idle_diff + nice_diff;

                    if (total_diff > 0) {
                        metrics.per_core_stats[i].user_percent = ((double)user_diff / total_diff) * 100.0;
                        metrics.per_core_stats[i].system_percent = ((double)sys_diff / total_diff) * 100.0;
                        metrics.per_core_stats[i].idle_percent = ((double)idle_diff / total_diff) * 100.0;
                        metrics.per_core_stats[i].usage_percent = 100.0 - metrics.per_core_stats[i].idle_percent;
                        total_usage += metrics.per_core_stats[i].usage_percent;
                    }
                }

                prev_cpu_info[i] = cpu_info[i];
            }

            metrics.overall_cpu_usage = total_usage / cpu_count;
            vm_deallocate(mach_task_self(), (vm_address_t)cpu_info, cpu_info_count);
        }

        // Memory statistics
        vm_statistics64_data_t vm_stat;
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;

        if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                             (host_info64_t)&vm_stat, &count) == KERN_SUCCESS) {

            uint64_t page_size;
            size_t size = sizeof(page_size);
            sysctlbyname("hw.pagesize", &page_size, &size, NULL, 0);

            uint64_t total_pages = vm_stat.free_count + vm_stat.active_count +
                                  vm_stat.inactive_count + vm_stat.wire_count;
            uint64_t used_pages = vm_stat.active_count + vm_stat.inactive_count + vm_stat.wire_count;

            metrics.memory_total_kb = (total_pages * page_size) / 1024;
            metrics.memory_available_kb = (vm_stat.free_count * page_size) / 1024;
            metrics.memory_usage_percent = ((double)used_pages / total_pages) * 100.0;

            metrics.page_faults = vm_stat.faults;
        }

        // Load averages
        double load_avg[3];
        if (getloadavg(load_avg, 3) != -1) {
            metrics.scheduler_stats.avg_load_1min = load_avg[0];
            metrics.scheduler_stats.avg_load_5min = load_avg[1];
            metrics.scheduler_stats.avg_load_15min = load_avg[2];
        }

        // Process information
        metrics.top_processes = collect_process_info();
        metrics.total_processes = metrics.top_processes.size();

        first_sample = false;
        return metrics;
    }

    void cleanup() override {
        // Nothing to cleanup for macOS
    }
};

#elif __linux__
class LinuxMonitor : public SystemMonitor {
private:
    struct CPUStats {
        uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    };

    uint32_t cpu_count;
    std::vector<CPUStats> prev_cpu_stats;
    bool first_sample;

    CPUStats parse_cpu_line(const std::string& line) {
        CPUStats stats = {};
        std::istringstream iss(line);
        std::string cpu_label;
        iss >> cpu_label >> stats.user >> stats.nice >> stats.system >> stats.idle
            >> stats.iowait >> stats.irq >> stats.softirq >> stats.steal;
        return stats;
    }

public:
    LinuxMonitor() : cpu_count(0), first_sample(true) {}

    uint32_t get_cpu_count() override {
        if (cpu_count == 0) {
            cpu_count = std::thread::hardware_concurrency();
            if (cpu_count == 0) cpu_count = 1;
        }
        return cpu_count;
    }

    bool initialize() override {
        cpu_count = get_cpu_count();
        prev_cpu_stats.resize(cpu_count + 1); // +1 for overall CPU stats

        // Read initial CPU stats
        std::ifstream stat_file("/proc/stat");
        std::string line;

        int cpu_index = 0;
        while (std::getline(stat_file, line) && cpu_index <= cpu_count) {
            if (line.substr(0, 3) == "cpu") {
                prev_cpu_stats[cpu_index] = parse_cpu_line(line);
                cpu_index++;
            }
        }

        return true;
    }

    std::vector<ProcessInfo> collect_process_info() {
        std::vector<ProcessInfo> processes;

        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) return processes;

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            if (!isdigit(entry->d_name[0])) continue;

            uint32_t pid = std::stoul(entry->d_name);
            ProcessInfo info = {};
            info.pid = pid;

            // Read /proc/[pid]/stat
            std::ifstream stat_file("/proc/" + std::string(entry->d_name) + "/stat");
            std::string stat_line;
            if (std::getline(stat_file, stat_line)) {
                std::istringstream iss(stat_line);
                std::string field;
                std::vector<std::string> fields;

                while (iss >> field) {
                    fields.push_back(field);
                }

                if (fields.size() >= 44) {
                    info.name = fields[1];
                    info.state = fields[2];
                    info.ppid = std::stoul(fields[3]);
                    info.priority = std::stol(fields[17]);
                    info.nice_value = std::stol(fields[18]);
                    info.current_cpu = std::stoul(fields[38]);
                    info.voluntary_context_switches = std::stoull(fields[41]);
                    info.involuntary_context_switches = std::stoull(fields[42]);
                    info.minor_faults = std::stoull(fields[9]);
                    info.major_faults = std::stoull(fields[11]);

                    // Calculate CPU time
                    uint64_t utime = std::stoull(fields[13]);
                    uint64_t stime = std::stoull(fields[14]);
                    info.cpu_time_ms = ((utime + stime) * 1000) / sysconf(_SC_CLK_TCK);
                }
            }

            // Read /proc/[pid]/status for additional info
            std::ifstream status_file("/proc/" + std::string(entry->d_name) + "/status");
            std::string status_line;
            while (std::getline(status_file, status_line)) {
                if (status_line.substr(0, 6) == "VmRSS:") {
                    std::istringstream iss(status_line);
                    std::string label, value, unit;
                    iss >> label >> value >> unit;
                    info.memory_rss = std::stoull(value) * 1024; // Convert kB to bytes
                } else if (status_line.substr(0, 6) == "VmSize:") {
                    std::istringstream iss(status_line);
                    std::string label, value, unit;
                    iss >> label >> value >> unit;
                    info.memory_vms = std::stoull(value) * 1024;
                }
            }

            // Check if it's a real-time process
            std::ifstream sched_file("/proc/" + std::string(entry->d_name) + "/sched");
            std::string sched_line;
            while (std::getline(sched_file, sched_line)) {
                if (sched_line.find("policy") != std::string::npos) {
                    if (sched_line.find("SCHED_FIFO") != std::string::npos ||
                        sched_line.find("SCHED_RR") != std::string::npos) {
                        info.is_realtime = true;
                    }
                    break;
                }
            }

            processes.push_back(info);
        }

        closedir(proc_dir);
        return processes;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // Per-core CPU statistics
        std::ifstream stat_file("/proc/stat");
        std::string line;
        std::vector<CPUStats> current_stats(cpu_count + 1);

        int cpu_index = 0;
        while (std::getline(stat_file, line) && cpu_index <= cpu_count) {
            if (line.substr(0, 3) == "cpu") {
                current_stats[cpu_index] = parse_cpu_line(line);
                cpu_index++;
            }
        }

        metrics.per_core_stats.resize(cpu_count);
        double total_usage = 0;

        if (!first_sample) {
            // Calculate per-core statistics
            for (uint32_t i = 1; i <= cpu_count; i++) { // Skip index 0 (overall CPU)
                const CPUStats& prev = prev_cpu_stats[i];
                const CPUStats& curr = current_stats[i];

                uint64_t prev_idle = prev.idle + prev.iowait;
                uint64_t curr_idle = curr.idle + curr.iowait;
                uint64_t prev_total = prev.user + prev.nice + prev.system + prev.idle +
                                     prev.iowait + prev.irq + prev.softirq + prev.steal;
                uint64_t curr_total = curr.user + curr.nice + curr.system + curr.idle +
                                     curr.iowait + curr.irq + curr.softirq + curr.steal;

                uint64_t total_diff = curr_total - prev_total;
                uint64_t idle_diff = curr_idle - prev_idle;

                if (total_diff > 0) {
                    metrics.per_core_stats[i-1].core_id = i - 1;
                    metrics.per_core_stats[i-1].usage_percent = ((double)(total_diff - idle_diff) / total_diff) * 100.0;
                    metrics.per_core_stats[i-1].user_percent = ((double)(curr.user - prev.user) / total_diff) * 100.0;
                    metrics.per_core_stats[i-1].system_percent = ((double)(curr.system - prev.system) / total_diff) * 100.0;
                    metrics.per_core_stats[i-1].idle_percent = ((double)idle_diff / total_diff) * 100.0;
                    metrics.per_core_stats[i-1].iowait_percent = ((double)(curr.iowait - prev.iowait) / total_diff) * 100.0;

                    total_usage += metrics.per_core_stats[i-1].usage_percent;
                }
            }

            metrics.overall_cpu_usage = total_usage / cpu_count;

            // Overall system statistics
            const CPUStats& prev_total = prev_cpu_stats[0];
            const CPUStats& curr_total = current_stats[0];
            uint64_t system_total_diff = (curr_total.user + curr_total.nice + curr_total.system +
                                         curr_total.idle + curr_total.iowait + curr_total.irq +
                                         curr_total.softirq + curr_total.steal) -
                                        (prev_total.user + prev_total.nice + prev_total.system +
                                         prev_total.idle + prev_total.iowait + prev_total.irq +
                                         prev_total.softirq + prev_total.steal);

            if (system_total_diff > 0) {
                metrics.overall_user_usage = ((double)(curr_total.user - prev_total.user) / system_total_diff) * 100.0;
                metrics.overall_system_usage = ((double)(curr_total.system - prev_total.system) / system_total_diff) * 100.0;
                metrics.overall_iowait = ((double)(curr_total.iowait - prev_total.iowait) / system_total_diff) * 100.0;
            }
        }

        prev_cpu_stats = current_stats;
        first_sample = false;

        // Memory information
        std::ifstream meminfo("/proc/meminfo");
        uint64_t mem_total = 0, mem_available = 0, swap_total = 0, swap_free = 0;

        while (std::getline(meminfo, line)) {
            std::istringstream iss(line);
            std::string label, unit;
            uint64_t value;

            if (iss >> label >> value >> unit) {
                if (label == "MemTotal:") mem_total = value;
                else if (label == "MemAvailable:") mem_available = value;
                else if (label == "SwapTotal:") swap_total = value;
                else if (label == "SwapFree:") swap_free = value;
            }
        }

        metrics.memory_total_kb = mem_total;
        metrics.memory_available_kb = mem_available;
        metrics.memory_usage_percent = ((double)(mem_total - mem_available) / mem_total) * 100.0;
        metrics.swap_total_kb = swap_total;
        metrics.swap_usage_kb = swap_total - swap_free;

        // Load averages
        std::ifstream loadavg("/proc/loadavg");
        loadavg >> metrics.scheduler_stats.avg_load_1min
                >> metrics.scheduler_stats.avg_load_5min
                >> metrics.scheduler_stats.avg_load_15min;

        // System statistics
        std::ifstream stat_file2("/proc/stat");
        while (std::getline(stat_file2, line)) {
            std::istringstream iss(line);
            std::string label;
            iss >> label;

            if (label == "ctxt") {
                iss >> metrics.scheduler_stats.total_context_switches;
            } else if (label == "procs_running") {
                iss >> metrics.scheduler_stats.total_runnable_tasks;
            } else if (label == "procs_blocked") {
                iss >> metrics.scheduler_stats.total_blocked_tasks;
            }
        }

        // Process information
        metrics.top_processes = collect_process_info();
        metrics.total_processes = metrics.top_processes.size();

        // Count real-time processes
        for (const auto& proc : metrics.top_processes) {
            if (proc.is_realtime) {
                metrics.scheduler_stats.realtime_processes++;
            } else {
                metrics.scheduler_stats.normal_processes++;
            }
        }

        // Sort processes by CPU usage and keep top 20
        std::sort(metrics.top_processes.begin(), metrics.top_processes.end(),
                  [](const ProcessInfo& a, const ProcessInfo& b) {
                      return a.cpu_time_ms > b.cpu_time_ms;
                  });

        if (metrics.top_processes.size() > 20) {
            metrics.top_processes.resize(20);
        }

        return metrics;
    }

    void cleanup() override {
        // Nothing to cleanup for Linux
    }
};

#elif __FreeBSD__
class FreeBSDMonitor : public SystemMonitor {
private:
    uint32_t cpu_count;
    std::vector<long> prev_cp_times;
    bool first_sample;

public:
    FreeBSDMonitor() : cpu_count(0), first_sample(true) {}

    uint32_t get_cpu_count() override {
        if (cpu_count == 0) {
            size_t size = sizeof(cpu_count);
            sysctlbyname("hw.ncpu", &cpu_count, &size, NULL, 0);
        }
        return cpu_count;
    }

    bool initialize() override {
        cpu_count = get_cpu_count();

        // Initialize per-CPU times
        size_t size = sizeof(long) * cpu_count * 5; // 5 states per CPU
        prev_cp_times.resize(cpu_count * 5);

        if (sysctlbyname("kern.cp_times", prev_cp_times.data(), &size, NULL, 0) != 0) {
            return false;
        }

        return true;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // Per-core CPU statistics
        std::vector<long> current_cp_times(cpu_count * 5);
        size_t size = sizeof(long) * cpu_count * 5;

        if (sysctlbyname("kern.cp_times", current_cp_times.data(), &size, NULL, 0) == 0) {
            metrics.per_core_stats.resize(cpu_count);
            double total_usage = 0;

            if (!first_sample) {
                for (uint32_t i = 0; i < cpu_count; i++) {
                    long* prev_core = &prev_cp_times[i * 5];
                    long* curr_core = &current_cp_times[i * 5];

                    long user_diff = curr_core[0] - prev_core[0];
                    long nice_diff = curr_core[1] - prev_core[1];
                    long sys_diff = curr_core[2] - prev_core[2];
                    long intr_diff = curr_core[3] - prev_core[3];
                    long idle_diff = curr_core[4] - prev_core[4];
                    long total_diff = user_diff + nice_diff + sys_diff + intr_diff + idle_diff;

                    if (total_diff > 0) {
                        metrics.per_core_stats[i].core_id = i;
                        metrics.per_core_stats[i].user_percent = ((double)user_diff / total_diff) * 100.0;
                        metrics.per_core_stats[i].system_percent = ((double)(sys_diff + intr_diff) / total_diff) * 100.0;
                        metrics.per_core_stats[i].idle_percent = ((double)idle_diff / total_diff) * 100.0;
                        metrics.per_core_stats[i].usage_percent = 100.0 - metrics.per_core_stats[i].idle_percent;

                        total_usage += metrics.per_core_stats[i].usage_percent;
                    }
                }

                metrics.overall_cpu_usage = total_usage / cpu_count;
            }

            prev_cp_times = current_cp_times;
            first_sample = false;
        }

        // Memory statistics
        u_long page_size;
        size = sizeof(page_size);
        sysctlbyname("hw.pagesize", &page_size, &size, NULL, 0);

        u_long mem_total, mem_free, mem_active, mem_inactive;
        size = sizeof(u_long);
        sysctlbyname("hw.physmem", &mem_total, &size, NULL, 0);
        sysctlbyname("vm.stats.vm.v_free_count", &mem_free, &size, NULL, 0);
        sysctlbyname("vm.stats.vm.v_active_count", &mem_active, &size, NULL, 0);
        sysctlbyname("vm.stats.vm.v_inactive_count", &mem_inactive, &size, NULL, 0);

        metrics.memory_total_kb = mem_total / 1024;
        metrics.memory_available_kb = (mem_free * page_size) / 1024;
        metrics.memory_usage_percent = ((double)((mem_active + mem_inactive) * page_size) / mem_total) * 100.0;

        // Load averages
        double load_avg[3];
        if (getloadavg(load_avg, 3) != -1) {
            metrics.scheduler_stats.avg_load_1min = load_avg[0];
            metrics.scheduler_stats.avg_load_5min = load_avg[1];
            metrics.scheduler_stats.avg_load_15min = load_avg[2];
        }

        return metrics;
    }

    void cleanup() override {
        // Nothing to cleanup for FreeBSD
    }
};
#endif

// Enhanced responsiveness test with latency measurements
class ResponsivenessTest {
private:
    std::atomic<bool> running{false};
    std::vector<double> response_times;
    std::vector<double> scheduler_latencies;
    std::mutex data_mutex;

public:
    void start() {
        running = true;
        response_times.clear();
        scheduler_latencies.clear();

        std::thread([this]() {
            while (running) {
                Timer timer;

                // Test 1: Simple computation latency
                timer.reset();
                volatile int sum = 0;
                for (int i = 0; i < 1000; i++) {
                    sum += i * i;
                }
                double compute_time = timer.elapsed_ms();

                // Test 2: Thread scheduling latency
                timer.reset();
                std::this_thread::yield();
                double schedule_time = timer.elapsed_ms();

                // Test 3: Memory allocation latency
                timer.reset();
                std::vector<int> temp_vec(1000);
                std::fill(temp_vec.begin(), temp_vec.end(), 42);
                double memory_time = timer.elapsed_ms();

                double total_response = compute_time + memory_time;

                {
                    std::lock_guard<std::mutex> lock(data_mutex);
                    response_times.push_back(total_response);
                    scheduler_latencies.push_back(schedule_time);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }).detach();
    }

    void stop() {
        running = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::pair<std::vector<double>, std::vector<double>> get_measurements() {
        std::lock_guard<std::mutex> lock(data_mutex);
        return {response_times, scheduler_latencies};
    }
};

// Main system profiler class
class SchedulerProfiler {
private:
    std::unique_ptr<SystemMonitor> monitor;
    ResponsivenessTest responsiveness;
    std::vector<SystemMetrics> metrics_history;
    std::atomic<bool> monitoring{false};
    std::string benchmark_command;
    Timer profiling_timer;

public:
    SchedulerProfiler() {
#ifdef _WIN32
        monitor = std::make_unique<WindowsMonitor>();
#elif __APPLE__
        monitor = std::make_unique<MacOSMonitor>();
#elif __linux__
        monitor = std::make_unique<LinuxMonitor>();
#elif __FreeBSD__
        monitor = std::make_unique<FreeBSDMonitor>();
#endif
    }

    bool initialize() {
        if (!monitor) return false;
        return monitor->initialize();
    }

    void set_benchmark_command(const std::string& command) {
        benchmark_command = command;
    }

    void start_monitoring() {
        monitoring = true;
        metrics_history.clear();
        responsiveness.start();
        profiling_timer.reset();

        std::thread([this]() {
            while (monitoring) {
                SystemMetrics metrics = monitor->collect_metrics();

                // Calculate responsiveness statistics from accumulated data
                auto [response_times, schedule_latencies] = responsiveness.get_measurements();
                if (!response_times.empty()) {
                    std::sort(response_times.begin(), response_times.end());
                    metrics.min_response_time_ms = response_times.front();
                    metrics.max_response_time_ms = response_times.back();
                    metrics.avg_response_time_ms = std::accumulate(response_times.begin(), response_times.end(), 0.0) / response_times.size();

                    size_t p95_idx = (response_times.size() * 95) / 100;
                    size_t p99_idx = (response_times.size() * 99) / 100;
                    if (p95_idx < response_times.size()) metrics.p95_response_time_ms = response_times[p95_idx];
                    if (p99_idx < response_times.size()) metrics.p99_response_time_ms = response_times[p99_idx];
                }

                if (!schedule_latencies.empty()) {
                    metrics.scheduler_stats.avg_scheduler_latency_ns =
                        std::accumulate(schedule_latencies.begin(), schedule_latencies.end(), 0.0) / schedule_latencies.size() * 1000000; // Convert ms to ns
                    metrics.scheduler_stats.max_scheduler_latency_ns =
                        *std::max_element(schedule_latencies.begin(), schedule_latencies.end()) * 1000000;
                }

                metrics_history.push_back(metrics);
                std::this_thread::sleep_for(std::chrono::milliseconds(250)); // Higher frequency for better scheduler analysis
            }
        }).detach();
    }

    void stop_monitoring() {
        monitoring = false;
        responsiveness.stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    int run_benchmark() {
        if (benchmark_command.empty()) {
            std::cerr << "No benchmark command specified\n";
            return -1;
        }

        std::cout << "Starting scheduler analysis with benchmark: " << benchmark_command << std::endl;
        start_monitoring();

        int result = std::system(benchmark_command.c_str());

        stop_monitoring();
        std::cout << "Benchmark completed with exit code: " << result << std::endl;

        return result;
    }

    void generate_comprehensive_report(const std::string& base_filename) {
        double total_duration = profiling_timer.elapsed_ms() / 1000.0;

        // Generate summary report
        generate_summary_report(base_filename + "_summary.txt", total_duration);

        // Generate time series data
        generate_timeseries_data(base_filename + "_timeseries.csv");

        // Generate per-core analysis
        generate_per_core_analysis(base_filename + "_per_core.csv");

        // Generate process analysis
        generate_process_analysis(base_filename + "_processes.csv");

        // Generate scheduler-specific metrics
        generate_scheduler_metrics(base_filename + "_scheduler.csv");
    }

private:
    void generate_summary_report(const std::string& filename, double duration) {
        std::ofstream report(filename);
        if (!report.is_open()) {
            std::cerr << "Failed to create summary report: " << filename << std::endl;
            return;
        }

        report << std::fixed << std::setprecision(2);
        report << "Enhanced Scheduler Performance Analysis Report\n";
        report << "============================================\n\n";

        report << "Platform: ";
#ifdef _WIN32
        report << "Windows\n";
#elif __APPLE__
        report << "macOS\n";
#elif __linux__
        report << "Linux\n";
#elif __FreeBSD__
        report << "FreeBSD\n";
#endif

        report << "CPU Cores: " << monitor->get_cpu_count() << "\n";
        report << "Benchmark Command: " << benchmark_command << "\n";
        report << "Total Duration: " << duration << " seconds\n";
        report << "Samples Collected: " << metrics_history.size() << "\n";
        report << "Sample Rate: " << (metrics_history.size() / duration) << " Hz\n\n";

        if (metrics_history.empty()) {
            report << "No data collected\n";
            return;
        }

        // Calculate aggregate statistics
        double avg_cpu = 0, max_cpu = 0, min_cpu = 100;
        double avg_memory = 0, max_memory = 0;
        double avg_load = 0, max_load = 0;
        double avg_response = 0, max_response = 0, min_response = 1000000;
        uint64_t total_context_switches = 0;
        uint32_t max_processes = 0;
        uint32_t max_realtime_processes = 0;

        for (const auto& metrics : metrics_history) {
            avg_cpu += metrics.overall_cpu_usage;
            avg_memory += metrics.memory_usage_percent;
            avg_load += metrics.scheduler_stats.avg_load_1min;
            avg_response += metrics.avg_response_time_ms;

            max_cpu = std::max(max_cpu, metrics.overall_cpu_usage);
            min_cpu = std::min(min_cpu, metrics.overall_cpu_usage);
            max_memory = std::max(max_memory, metrics.memory_usage_percent);
            max_load = std::max(max_load, metrics.scheduler_stats.avg_load_1min);
            max_response = std::max(max_response, metrics.max_response_time_ms);
            min_response = std::min(min_response, metrics.min_response_time_ms);

            total_context_switches += metrics.scheduler_stats.total_context_switches;
            max_processes = std::max(max_processes, metrics.total_processes);
            max_realtime_processes = std::max(max_realtime_processes, metrics.scheduler_stats.realtime_processes);
        }

        size_t count = metrics_history.size();
        avg_cpu /= count;
        avg_memory /= count;
        avg_load /= count;
        avg_response /= count;

        report << "=== CPU UTILIZATION ===\n";
        report << "Average CPU Usage: " << avg_cpu << "%\n";
        report << "Maximum CPU Usage: " << max_cpu << "%\n";
        report << "Minimum CPU Usage: " << min_cpu << "%\n";
        report << "CPU Usage Range: " << (max_cpu - min_cpu) << "%\n\n";

        report << "=== MEMORY UTILIZATION ===\n";
        report << "Average Memory Usage: " << avg_memory << "%\n";
        report << "Maximum Memory Usage: " << max_memory << "%\n";
        if (!metrics_history.empty()) {
            report << "Memory Total: " << (metrics_history.back().memory_total_kb / 1024) << " MB\n";
            report << "Swap Usage: " << (metrics_history.back().swap_usage_kb / 1024) << " MB\n\n";
        }

        report << "=== SCHEDULER PERFORMANCE ===\n";
        report << "Average Load (1min): " << avg_load << "\n";
        report << "Maximum Load (1min): " << max_load << "\n";
        report << "Load Efficiency: " << ((avg_load / monitor->get_cpu_count()) * 100) << "% (vs CPU count)\n";
        report << "Context Switches/sec: " << (total_context_switches / duration) << "\n";
        report << "Peak Process Count: " << max_processes << "\n";
        report << "Peak RT Process Count: " << max_realtime_processes << "\n\n";

        report << "=== RESPONSIVENESS ANALYSIS ===\n";
        report << "Average Response Time: " << avg_response << " ms\n";
        report << "Minimum Response Time: " << min_response << " ms\n";
        report << "Maximum Response Time: " << max_response << " ms\n";

        // Calculate percentiles from last measurement
        if (!metrics_history.empty()) {
            const auto& last_metrics = metrics_history.back();
            report << "95th Percentile Response: " << last_metrics.p95_response_time_ms << " ms\n";
            report << "99th Percentile Response: " << last_metrics.p99_response_time_ms << " ms\n";
            report << "Avg Scheduler Latency: " << (last_metrics.scheduler_stats.avg_scheduler_latency_ns / 1000000.0) << " ms\n";
            report << "Max Scheduler Latency: " << (last_metrics.scheduler_stats.max_scheduler_latency_ns / 1000000.0) << " ms\n\n";
        }

        // Per-core load balancing analysis
        report << "=== LOAD BALANCING ANALYSIS ===\n";
        if (!metrics_history.empty() && !metrics_history.back().per_core_stats.empty()) {
            double core_usage_sum = 0;
            double core_usage_variance = 0;
            std::vector<double> core_averages(monitor->get_cpu_count(), 0);

            // Calculate per-core averages
            for (const auto& metrics : metrics_history) {
                for (size_t i = 0; i < metrics.per_core_stats.size() && i < core_averages.size(); i++) {
                    core_averages[i] += metrics.per_core_stats[i].usage_percent;
                }
            }

            for (auto& avg : core_averages) {
                avg /= count;
                core_usage_sum += avg;
            }

            double mean_core_usage = core_usage_sum / core_averages.size();

            // Calculate variance
            for (double avg : core_averages) {
                core_usage_variance += (avg - mean_core_usage) * (avg - mean_core_usage);
            }
            core_usage_variance /= core_averages.size();

            report << "Mean Core Usage: " << mean_core_usage << "%\n";
            report << "Core Usage Std Dev: " << std::sqrt(core_usage_variance) << "%\n";
            report << "Load Balance Quality: " << (100.0 - (std::sqrt(core_usage_variance) / mean_core_usage * 100)) << "% (higher is better)\n\n";

            report << "Per-Core Average Utilization:\n";
            for (size_t i = 0; i < core_averages.size(); i++) {
                report << "  Core " << i << ": " << core_averages[i] << "%\n";
            }
        }

        report << "\n=== PERFORMANCE RECOMMENDATIONS ===\n";
        if (avg_cpu > 80) {
            report << "- High CPU utilization detected. Consider CPU-bound optimizations.\n";
        }
        if (max_load > monitor->get_cpu_count() * 1.5) {
            report << "- System load exceeds CPU capacity. Consider load balancing.\n";
        }
        if (avg_response > 10) {
            report << "- High response times detected. Check for scheduling delays.\n";
        }
        if (max_realtime_processes > 0) {
            report << "- Real-time processes detected. Monitor RT scheduling impact.\n";
        }

        std::cout << "Summary report generated: " << filename << std::endl;
    }

    void generate_timeseries_data(const std::string& filename) {
        std::ofstream csv(filename);
        if (!csv.is_open()) {
            std::cerr << "Failed to create timeseries file: " << filename << std::endl;
            return;
        }

        // Header
        csv << "timestamp_ms,overall_cpu_pct,overall_user_pct,overall_system_pct,overall_iowait_pct,"
            << "memory_usage_pct,memory_available_kb,swap_usage_kb,"
            << "load_1min,load_5min,load_15min,"
            << "total_context_switches,runnable_tasks,blocked_tasks,"
            << "total_processes,realtime_processes,active_threads,"
            << "min_response_ms,avg_response_ms,max_response_ms,p95_response_ms,p99_response_ms,"
            << "avg_scheduler_latency_ns,max_scheduler_latency_ns,"
            << "page_faults,cache_misses,instructions_per_cycle\n";

        // Data rows
        for (const auto& metrics : metrics_history) {
            auto time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                metrics.timestamp.time_since_epoch()).count();

            csv << time_ms << ","
                << metrics.overall_cpu_usage << ","
                << metrics.overall_user_usage << ","
                << metrics.overall_system_usage << ","
                << metrics.overall_iowait << ","
                << metrics.memory_usage_percent << ","
                << metrics.memory_available_kb << ","
                << metrics.swap_usage_kb << ","
                << metrics.scheduler_stats.avg_load_1min << ","
                << metrics.scheduler_stats.avg_load_5min << ","
                << metrics.scheduler_stats.avg_load_15min << ","
                << metrics.scheduler_stats.total_context_switches << ","
                << metrics.scheduler_stats.total_runnable_tasks << ","
                << metrics.scheduler_stats.total_blocked_tasks << ","
                << metrics.total_processes << ","
                << metrics.scheduler_stats.realtime_processes << ","
                << metrics.active_threads << ","
                << metrics.min_response_time_ms << ","
                << metrics.avg_response_time_ms << ","
                << metrics.max_response_time_ms << ","
                << metrics.p95_response_time_ms << ","
                << metrics.p99_response_time_ms << ","
                << metrics.scheduler_stats.avg_scheduler_latency_ns << ","
                << metrics.scheduler_stats.max_scheduler_latency_ns << ","
                << metrics.page_faults << ","
                << metrics.cache_misses << ","
                << metrics.instructions_per_cycle << "\n";
        }

        std::cout << "Time series data generated: " << filename << std::endl;
    }

    void generate_per_core_analysis(const std::string& filename) {
        std::ofstream csv(filename);
        if (!csv.is_open()) {
            std::cerr << "Failed to create per-core file: " << filename << std::endl;
            return;
        }

        // Headers
        csv << "timestamp_ms,core_id,usage_pct,user_pct,system_pct,idle_pct,iowait_pct,"
            << "interrupts,context_switches,cache_misses,frequency_mhz\n";

        // Data
        for (const auto& metrics : metrics_history) {
            auto time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                metrics.timestamp.time_since_epoch()).count();

            for (const auto& core : metrics.per_core_stats) {
                csv << time_ms << ","
                    << core.core_id << ","
                    << core.usage_percent << ","
                    << core.user_percent << ","
                    << core.system_percent << ","
                    << core.idle_percent << ","
                    << core.iowait_percent << ","
                    << core.interrupts << ","
                    << core.context_switches << ","
                    << core.cache_misses << ","
                    << core.frequency_mhz << "\n";
            }
        }

        std::cout << "Per-core analysis generated: " << filename << std::endl;
    }

    void generate_process_analysis(const std::string& filename) {
        std::ofstream csv(filename);
        if (!csv.is_open()) {
            std::cerr << "Failed to create process file: " << filename << std::endl;
            return;
        }

        csv << "timestamp_ms,pid,ppid,tid,name,priority,nice_value,state,cpu_affinity,current_cpu,"
            << "voluntary_ctx_switches,involuntary_ctx_switches,cpu_time_ms,memory_rss,memory_vms,"
            << "page_faults,minor_faults,major_faults,scheduler_latency_ns,is_realtime,scheduler_policy\n";

        for (const auto& metrics : metrics_history) {
            auto time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                metrics.timestamp.time_since_epoch()).count();

            for (const auto& proc : metrics.top_processes) {
                csv << time_ms << ","
                    << proc.pid << ","
                    << proc.ppid << ","
                    << proc.tid << ","
                    << "\"" << proc.name << "\","
                    << proc.priority << ","
                    << proc.nice_value << ","
                    << "\"" << proc.state << "\","
                    << proc.cpu_affinity << ","
                    << proc.current_cpu << ","
                    << proc.voluntary_context_switches << ","
                    << proc.involuntary_context_switches << ","
                    << proc.cpu_time_ms << ","
                    << proc.memory_rss << ","
                    << proc.memory_vms << ","
                    << proc.page_faults << ","
                    << proc.minor_faults << ","
                    << proc.major_faults << ","
                    << proc.scheduler_latency_ns << ","
                    << (proc.is_realtime ? 1 : 0) << ","
                    << proc.scheduler_policy << "\n";
            }
        }

        std::cout << "Process analysis generated: " << filename << std::endl;
    }

    void generate_scheduler_metrics(const std::string& filename) {
        std::ofstream csv(filename);
        if (!csv.is_open()) {
            std::cerr << "Failed to create scheduler metrics file: " << filename << std::endl;
            return;
        }

        csv << "timestamp_ms,runqueue_length_core0,runqueue_length_core1,runqueue_length_core2,runqueue_length_core3,"
            << "total_runnable,total_blocked,total_sleeping,voluntary_ctx_switches,involuntary_ctx_switches,"
            << "avg_scheduler_latency_ns,max_scheduler_latency_ns,realtime_processes,normal_processes\n";

        for (const auto& metrics : metrics_history) {
            auto time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                metrics.timestamp.time_since_epoch()).count();

            csv << time_ms << ",";

            // Runqueue lengths (pad with zeros if not enough cores reported)
            for (int i = 0; i < 4; i++) {
                if (i < metrics.scheduler_stats.runqueue_lengths.size()) {
                    csv << metrics.scheduler_stats.runqueue_lengths[i];
                } else {
                    csv << "0";
                }
                csv << ",";
            }

            csv << metrics.scheduler_stats.total_runnable_tasks << ","
                << metrics.scheduler_stats.total_blocked_tasks << ","
                << metrics.scheduler_stats.total_sleeping_tasks << ","
                << metrics.scheduler_stats.voluntary_context_switches << ","
                << metrics.scheduler_stats.involuntary_context_switches << ","
                << metrics.scheduler_stats.avg_scheduler_latency_ns << ","
                << metrics.scheduler_stats.max_scheduler_latency_ns << ","
                << metrics.scheduler_stats.realtime_processes << ","
                << metrics.scheduler_stats.normal_processes << "\n";
        }

        std::cout << "Scheduler metrics generated: " << filename << std::endl;
    }

public:
    void cleanup() {
        if (monitor) {
            monitor->cleanup();
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Enhanced Cross-Platform Scheduler Profiler\n";
        std::cout << "Usage: " << argv[0] << " <benchmark_command> [output_prefix]\n\n";
        std::cout << "Examples:\n";
        std::cout << "  Linux:   " << argv[0] << " \"stress-ng --cpu 4 --timeout 30s\" stress_test\n";
        std::cout << "  Windows: " << argv[0] << " \"powershell -c 'for($i=0;$i -lt 1000000;$i++){1+1}'\" compute_test\n";
        std::cout << "  macOS:   " << argv[0] << " \"yes > /dev/null\" cpu_test\n\n";
        std::cout << "Output files generated:\n";
        std::cout << "  *_summary.txt     - Human-readable analysis summary\n";
        std::cout << "  *_timeseries.csv  - Time series data for detailed analysis\n";
        std::cout << "  *_per_core.csv    - Per-CPU core utilization data\n";
        std::cout << "  *_processes.csv   - Process scheduling information\n";
        std::cout << "  *_scheduler.csv   - Scheduler-specific metrics\n";
        return 1;
    }

    SchedulerProfiler profiler;

    if (!profiler.initialize()) {
        std::cerr << "Failed to initialize scheduler profiler\n";
        return 1;
    }

    profiler.set_benchmark_command(argv[1]);

    std::cout << "Enhanced Scheduler Performance Profiler\n";
    std::cout << "======================================\n";
    std::cout << "Collecting comprehensive scheduler metrics...\n\n";

    int benchmark_result = profiler.run_benchmark();

    std::string output_prefix = (argc > 2) ? argv[2] : "scheduler_profile";
    profiler.generate_comprehensive_report(output_prefix);

    std::cout << "\nProfiler completed successfully!\n";
    std::cout << "Benchmark exit code: " << benchmark_result << "\n";

    profiler.cleanup();
    return benchmark_result;
}