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

#ifdef _WIN32
#define NOMINMAX  // Prevent Windows.h from defining min/max macros
#include <windows.h>
#include <pdh.h>
#include <psapi.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")

// Define PDH constants that might be missing
#ifndef PDH_CSTATUS_VALID_DATA
#define PDH_CSTATUS_VALID_DATA 0x00000000L
#endif
#ifndef PDH_INVALID_DATA
#define PDH_INVALID_DATA 0xC0000BF6L
#endif
#elif __APPLE__
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#elif __linux__
#include <unistd.h>
#include <sys/times.h>
#include <fstream>
#elif __FreeBSD__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
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
};

// System metrics structure
struct SystemMetrics {
    double cpu_usage_percent;
    double memory_usage_percent;
    uint64_t context_switches;
    uint64_t interrupts;
    double load_average;
    uint64_t running_processes;
    double io_wait_percent;
    std::chrono::system_clock::time_point timestamp;
};

// Platform-specific system monitor interface
class SystemMonitor {
public:
    virtual ~SystemMonitor() = default;
    virtual bool initialize() = 0;
    virtual SystemMetrics collect_metrics() = 0;
    virtual void cleanup() = 0;
};

#ifdef _WIN32
class WindowsMonitor : public SystemMonitor {
private:
    PDH_HQUERY query;
    PDH_HCOUNTER cpu_counter;
    PDH_HCOUNTER memory_available_counter;
    PDH_HCOUNTER context_switch_counter;
    PDH_HCOUNTER interrupt_counter;
    bool first_sample;
    MEMORYSTATUSEX prev_memory_status;

public:
    WindowsMonitor() : query(NULL), first_sample(true) {
        memset(&prev_memory_status, 0, sizeof(prev_memory_status));
        prev_memory_status.dwLength = sizeof(prev_memory_status);
    }

    bool initialize() override {
        PDH_STATUS status;

        // Open PDH query
        status = PdhOpenQueryW(NULL, 0, &query);
        if (status != ERROR_SUCCESS) {
            std::cerr << "PdhOpenQuery failed with status: " << status << std::endl;
            return false;
        }

        // Add CPU counter with better error handling
        status = PdhAddEnglishCounterW(query, L"\\Processor(_Total)\\% Processor Time", 0, &cpu_counter);
        if (status != ERROR_SUCCESS) {
            std::cerr << "Failed to add CPU counter: " << status << std::endl;
            // Try alternative counter
            status = PdhAddCounterW(query, L"\\Processor(_Total)\\% Processor Time", 0, &cpu_counter);
            if (status != ERROR_SUCCESS) {
                std::cerr << "Failed to add CPU counter (alternative): " << status << std::endl;
            }
        }

        // Add memory available counter (better than committed bytes)
        status = PdhAddEnglishCounterW(query, L"\\Memory\\Available Bytes", 0, &memory_available_counter);
        if (status != ERROR_SUCCESS) {
            std::cerr << "Failed to add memory counter: " << status << std::endl;
            status = PdhAddCounterW(query, L"\\Memory\\Available Bytes", 0, &memory_available_counter);
        }

        // Add context switches counter
        status = PdhAddEnglishCounterW(query, L"\\System\\Context Switches/sec", 0, &context_switch_counter);
        if (status != ERROR_SUCCESS) {
            status = PdhAddCounterW(query, L"\\System\\Context Switches/sec", 0, &context_switch_counter);
        }

        // Add interrupts counter
        status = PdhAddEnglishCounterW(query, L"\\Processor(_Total)\\Interrupts/sec", 0, &interrupt_counter);
        if (status != ERROR_SUCCESS) {
            status = PdhAddCounterW(query, L"\\Processor(_Total)\\Interrupts/sec", 0, &interrupt_counter);
        }

        // Initial collection - ignore PDH_INVALID_DATA on first call
        PdhCollectQueryData(query);
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Longer delay for Windows 11 compatibility

        // Second collection to establish baseline
        PdhCollectQueryData(query);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        return true;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // Collect PDH data
        PDH_STATUS status = PdhCollectQueryData(query);
        if (status == ERROR_SUCCESS) {
            PDH_FMT_COUNTERVALUE counter_value;

            // CPU Usage
            status = PdhGetFormattedCounterValue(cpu_counter, PDH_FMT_DOUBLE, NULL, &counter_value);
            if (status == ERROR_SUCCESS && counter_value.CStatus == PDH_CSTATUS_VALID_DATA) {
                metrics.cpu_usage_percent = counter_value.doubleValue;
                // Handle Windows 11 issue where values can be > 100%
                if (metrics.cpu_usage_percent > 100.0) {
                    metrics.cpu_usage_percent = metrics.cpu_usage_percent / GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
                }
            } else if (status == PDH_INVALID_DATA && !first_sample) {
                // Handle PDH_INVALID_DATA by keeping previous value
                metrics.cpu_usage_percent = 0.0;
            }

            // Memory Usage (calculate from available bytes)
            status = PdhGetFormattedCounterValue(memory_available_counter, PDH_FMT_LARGE, NULL, &counter_value);
            if (status == ERROR_SUCCESS && counter_value.CStatus == PDH_CSTATUS_VALID_DATA) {
                MEMORYSTATUSEX mem_status;
                mem_status.dwLength = sizeof(mem_status);
                if (GlobalMemoryStatusEx(&mem_status)) {
                    metrics.memory_usage_percent = ((double)(mem_status.ullTotalPhys - counter_value.largeValue) / mem_status.ullTotalPhys) * 100.0;
                }
            }

            // Context Switches
            status = PdhGetFormattedCounterValue(context_switch_counter, PDH_FMT_LARGE, NULL, &counter_value);
            if (status == ERROR_SUCCESS && counter_value.CStatus == PDH_CSTATUS_VALID_DATA) {
                metrics.context_switches = counter_value.largeValue;
            }

            // Interrupts
            status = PdhGetFormattedCounterValue(interrupt_counter, PDH_FMT_LARGE, NULL, &counter_value);
            if (status == ERROR_SUCCESS && counter_value.CStatus == PDH_CSTATUS_VALID_DATA) {
                metrics.interrupts = counter_value.largeValue;
            }
        }

        // Get additional system information
        PERFORMANCE_INFORMATION perf_info;
        if (GetPerformanceInfo(&perf_info, sizeof(perf_info))) {
            metrics.running_processes = perf_info.ProcessCount;
        }

        // Calculate load average equivalent (not directly available on Windows)
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        metrics.load_average = (metrics.cpu_usage_percent / 100.0) * sys_info.dwNumberOfProcessors;

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
    host_cpu_load_info_data_t prev_cpu_info;
    bool first_sample;

public:
    MacOSMonitor() : first_sample(true) {}

    bool initialize() override {
        // Get initial CPU sample
        mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
        host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                       (host_info_t)&prev_cpu_info, &count);
        return true;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // CPU Usage
        host_cpu_load_info_data_t cpu_info;
        mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;

        if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                           (host_info_t)&cpu_info, &count) == KERN_SUCCESS) {

            if (!first_sample) {
                uint64_t user_diff = cpu_info.cpu_ticks[CPU_STATE_USER] - prev_cpu_info.cpu_ticks[CPU_STATE_USER];
                uint64_t sys_diff = cpu_info.cpu_ticks[CPU_STATE_SYSTEM] - prev_cpu_info.cpu_ticks[CPU_STATE_SYSTEM];
                uint64_t idle_diff = cpu_info.cpu_ticks[CPU_STATE_IDLE] - prev_cpu_info.cpu_ticks[CPU_STATE_IDLE];
                uint64_t total_diff = user_diff + sys_diff + idle_diff;

                if (total_diff > 0) {
                    metrics.cpu_usage_percent = ((double)(user_diff + sys_diff) / total_diff) * 100.0;
                }
            }
            prev_cpu_info = cpu_info;
            first_sample = false;
        }

        // Memory Usage
        vm_statistics64_data_t vm_stat;
        count = HOST_VM_INFO64_COUNT;
        if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                             (host_info64_t)&vm_stat, &count) == KERN_SUCCESS) {

            uint64_t total_pages = vm_stat.free_count + vm_stat.active_count +
                                  vm_stat.inactive_count + vm_stat.wire_count;
            uint64_t used_pages = vm_stat.active_count + vm_stat.inactive_count + vm_stat.wire_count;

            if (total_pages > 0) {
                metrics.memory_usage_percent = ((double)used_pages / total_pages) * 100.0;
            }
        }

        // Load Average
        double load_avg[3];
        if (getloadavg(load_avg, 3) != -1) {
            metrics.load_average = load_avg[0];
        }

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

    CPUStats prev_cpu_stats;
    bool first_sample;

    CPUStats read_cpu_stats() {
        CPUStats stats = {};
        std::ifstream file("/proc/stat");
        std::string line;

        if (std::getline(file, line) && line.substr(0, 3) == "cpu") {
            std::istringstream iss(line);
            std::string cpu_label;
            iss >> cpu_label >> stats.user >> stats.nice >> stats.system >> stats.idle
                >> stats.iowait >> stats.irq >> stats.softirq >> stats.steal;
        }

        return stats;
    }

public:
    LinuxMonitor() : first_sample(true) {}

    bool initialize() override {
        prev_cpu_stats = read_cpu_stats();
        return true;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // CPU Usage
        CPUStats current_stats = read_cpu_stats();

        if (!first_sample) {
            uint64_t prev_idle = prev_cpu_stats.idle + prev_cpu_stats.iowait;
            uint64_t curr_idle = current_stats.idle + current_stats.iowait;

            uint64_t prev_total = prev_cpu_stats.user + prev_cpu_stats.nice + prev_cpu_stats.system +
                                 prev_cpu_stats.idle + prev_cpu_stats.iowait + prev_cpu_stats.irq +
                                 prev_cpu_stats.softirq + prev_cpu_stats.steal;
            uint64_t curr_total = current_stats.user + current_stats.nice + current_stats.system +
                                 current_stats.idle + current_stats.iowait + current_stats.irq +
                                 current_stats.softirq + current_stats.steal;

            uint64_t total_diff = curr_total - prev_total;
            uint64_t idle_diff = curr_idle - prev_idle;

            if (total_diff > 0) {
                metrics.cpu_usage_percent = ((double)(total_diff - idle_diff) / total_diff) * 100.0;
                metrics.io_wait_percent = ((double)(current_stats.iowait - prev_cpu_stats.iowait) / total_diff) * 100.0;
            }
        }

        prev_cpu_stats = current_stats;
        first_sample = false;

        // Memory Usage
        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        uint64_t mem_total = 0, mem_available = 0;

        while (std::getline(meminfo, line)) {
            if (line.substr(0, 9) == "MemTotal:") {
                std::istringstream iss(line);
                std::string label, unit;
                iss >> label >> mem_total >> unit;
            } else if (line.substr(0, 12) == "MemAvailable:") {
                std::istringstream iss(line);
                std::string label, unit;
                iss >> label >> mem_available >> unit;
            }
        }

        if (mem_total > 0) {
            metrics.memory_usage_percent = ((double)(mem_total - mem_available) / mem_total) * 100.0;
        }

        // Load Average
        std::ifstream loadavg("/proc/loadavg");
        if (loadavg.is_open()) {
            loadavg >> metrics.load_average;
        }

        // Context Switches
        std::ifstream stat("/proc/stat");
        while (std::getline(stat, line)) {
            if (line.substr(0, 4) == "ctxt") {
                std::istringstream iss(line);
                std::string label;
                iss >> label >> metrics.context_switches;
                break;
            }
        }

        return metrics;
    }

    void cleanup() override {
        // Nothing to cleanup for Linux
    }
};

#elif __FreeBSD__
class FreeBSDMonitor : public SystemMonitor {
public:
    bool initialize() override {
        return true;
    }

    SystemMetrics collect_metrics() override {
        SystemMetrics metrics = {};
        metrics.timestamp = std::chrono::system_clock::now();

        // CPU Usage via sysctl
        size_t size;
        long cp_time[5];
        static long prev_cp_time[5] = {0};
        static bool first_sample = true;

        size = sizeof(cp_time);
        if (sysctlbyname("kern.cp_time", &cp_time, &size, NULL, 0) == 0) {
            if (!first_sample) {
                long user_diff = cp_time[0] - prev_cp_time[0];
                long nice_diff = cp_time[1] - prev_cp_time[1];
                long sys_diff = cp_time[2] - prev_cp_time[2];
                long idle_diff = cp_time[4] - prev_cp_time[4];
                long total_diff = user_diff + nice_diff + sys_diff + idle_diff;

                if (total_diff > 0) {
                    metrics.cpu_usage_percent = ((double)(total_diff - idle_diff) / total_diff) * 100.0;
                }
            }

            for (int i = 0; i < 5; i++) {
                prev_cp_time[i] = cp_time[i];
            }
            first_sample = false;
        }

        // Load Average
        double load_avg[3];
        if (getloadavg(load_avg, 3) != -1) {
            metrics.load_average = load_avg[0];
        }

        return metrics;
    }

    void cleanup() override {
        // Nothing to cleanup for FreeBSD
    }
};
#endif

// Responsiveness test - measures how quickly the system responds to simple operations
class ResponsivenessTest {
private:
    std::atomic<bool> running{false};
    std::vector<double> response_times;
    std::mutex response_mutex;

public:
    void start() {
        running = true;
        response_times.clear();

        std::thread([this]() {
            while (running) {
                Timer timer;

                // Simple file operation test
                timer.reset();
                {
                    std::ofstream temp_file("responsiveness_test.tmp");
                    temp_file << "test" << std::flush;
                }
                double file_time = timer.elapsed_ms();

                // Memory allocation test
                timer.reset();
                {
                    std::vector<int> temp_vec(1000);
                    std::fill(temp_vec.begin(), temp_vec.end(), 42);
                }
                double memory_time = timer.elapsed_ms();

                // Combined response time
                double total_time = file_time + memory_time;

                {
                    std::lock_guard<std::mutex> lock(response_mutex);
                    response_times.push_back(total_time);
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();
    }

    void stop() {
        running = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        std::remove("responsiveness_test.tmp");
    }

    std::vector<double> get_response_times() {
        std::lock_guard<std::mutex> lock(response_mutex);
        return response_times;
    }
};

// Main monitoring class
class SystemProfiler {
private:
    std::unique_ptr<SystemMonitor> monitor;
    ResponsivenessTest responsiveness;
    std::vector<SystemMetrics> metrics_history;
    std::atomic<bool> monitoring{false};
    std::string benchmark_command;

public:
    SystemProfiler() {
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
        return monitor->initialize();
    }

    void set_benchmark_command(const std::string& command) {
        benchmark_command = command;
    }

    void start_monitoring() {
        monitoring = true;
        metrics_history.clear();
        responsiveness.start();

        std::thread([this]() {
            while (monitoring) {
                SystemMetrics metrics = monitor->collect_metrics();
                metrics_history.push_back(metrics);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }).detach();
    }

    void stop_monitoring() {
        monitoring = false;
        responsiveness.stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
    }

    int run_benchmark() {
        if (benchmark_command.empty()) {
            std::cerr << "No benchmark command specified\n";
            return -1;
        }

        std::cout << "Starting benchmark: " << benchmark_command << std::endl;
        start_monitoring();

        int result = std::system(benchmark_command.c_str());

        stop_monitoring();
        std::cout << "Benchmark completed with exit code: " << result << std::endl;

        return result;
    }

    void generate_report(const std::string& filename) {
        std::ofstream report(filename);
        if (!report.is_open()) {
            std::cerr << "Failed to create report file: " << filename << std::endl;
            return;
        }

        report << "System Responsiveness Monitoring Report\n";
        report << "======================================\n\n";

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

        report << "Benchmark Command: " << benchmark_command << "\n";
        report << "Monitoring Duration: " << metrics_history.size() * 0.5 << " seconds\n\n";

        // Calculate statistics
        if (!metrics_history.empty()) {
            double avg_cpu = 0, max_cpu = 0, avg_memory = 0, max_memory = 0;
            double avg_load = 0, max_load = 0;

            for (const auto& metrics : metrics_history) {
                avg_cpu += metrics.cpu_usage_percent;
                avg_memory += metrics.memory_usage_percent;
                avg_load += metrics.load_average;

                max_cpu = (max_cpu > metrics.cpu_usage_percent) ? max_cpu : metrics.cpu_usage_percent;
                max_memory = (max_memory > metrics.memory_usage_percent) ? max_memory : metrics.memory_usage_percent;
                max_load = (max_load > metrics.load_average) ? max_load : metrics.load_average;
            }

            size_t count = metrics_history.size();
            avg_cpu /= count;
            avg_memory /= count;
            avg_load /= count;

            report << "CPU Usage: Average " << avg_cpu << "%, Maximum " << max_cpu << "%\n";
            report << "Memory Usage: Average " << avg_memory << "%, Maximum " << max_memory << "%\n";
            report << "Load Average: Average " << avg_load << ", Maximum " << max_load << "\n\n";
        }

        // Responsiveness statistics
        auto response_times = responsiveness.get_response_times();
        if (!response_times.empty()) {
            double avg_response = 0, max_response = 0;
            for (double time : response_times) {
                avg_response += time;
                max_response = (max_response > time) ? max_response : time;
            }
            avg_response /= response_times.size();

            report << "Application Responsiveness:\n";
            report << "  Average Response Time: " << avg_response << " ms\n";
            report << "  Maximum Response Time: " << max_response << " ms\n";
            report << "  Total Samples: " << response_times.size() << "\n\n";
        }

        // Detailed timeline
        report << "Detailed Timeline (CSV format):\n";
        report << "Timestamp,CPU%,Memory%,LoadAvg,IOWait%,ContextSwitches\n";

        for (const auto& metrics : metrics_history) {
            auto time_t = std::chrono::system_clock::to_time_t(metrics.timestamp);

            report << time_t << ","
                   << metrics.cpu_usage_percent << ","
                   << metrics.memory_usage_percent << ","
                   << metrics.load_average << ","
                   << metrics.io_wait_percent << ","
                   << metrics.context_switches << "\n";
        }

        report.close();
        std::cout << "Report generated: " << filename << std::endl;
    }

    void cleanup() {
        monitor->cleanup();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <benchmark_command> [report_file]\n";
        std::cout << "Example: " << argv[0] << " \"stress-ng --cpu 4 --timeout 30s\" report.txt\n";
        return 1;
    }

    SystemProfiler profiler;

    if (!profiler.initialize()) {
        std::cerr << "Failed to initialize system profiler\n";
        return 1;
    }

    profiler.set_benchmark_command(argv[1]);

    std::cout << "System Responsiveness Profiler\n";
    std::cout << "==============================\n";

    int benchmark_result = profiler.run_benchmark();

    std::string report_file = (argc > 2) ? argv[2] : "profiler_report.txt";
    profiler.generate_report(report_file);

    profiler.cleanup();

    return benchmark_result;
}