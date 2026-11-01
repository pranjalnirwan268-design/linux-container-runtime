#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

struct ContainerConfig {
    std::filesystem::path rootfs_path = "./rootfs";
    std::string hostname = "container-isolated";
    std::string command = "/bin/sh";
    std::vector<std::string> args = {"/bin/sh"};

    // Resource boundaries
    uint64_t memory_limit_bytes = 100 * 1024 * 1024; // 100MB
    uint64_t cpu_max_quota_us = 50000;              // 50ms (50% CPU)
    uint64_t cpu_max_period_us = 100000;            // 100ms
};
