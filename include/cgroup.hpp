#pragma once
#include "config.hpp"
#include <sys/types.h>
#include <string>

class CgroupController {
public:
    explicit CgroupController(pid_t child_pid, const ContainerConfig& config);
    ~CgroupController();

    // Non-copyable / non-movable: owns a unique cgroup subtree directory.
    CgroupController(const CgroupController&) = delete;
    CgroupController& operator=(const CgroupController&) = delete;

    void apply_limits();

private:
    pid_t pid_;
    ContainerConfig config_;
    std::string cgroup_path_;
};
