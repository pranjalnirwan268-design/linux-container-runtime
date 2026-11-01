#include "cgroup.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <system_error>

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

namespace {

constexpr const char* kCgroupRoot = "/sys/fs/cgroup";

// Write a value into a cgroup control file. Host-side code, so throwing on
// failure is appropriate and surfaced to the caller.
void write_cgroup_file(const std::string& path, const std::string& value) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        throw std::system_error(errno, std::generic_category(),
                                "open " + path);
    }

    ssize_t written = 0;
    const char* buf = value.data();
    size_t remaining = value.size();
    while (remaining > 0) {
        written = ::write(fd, buf, remaining);
        if (written == -1) {
            if (errno == EINTR) {
                continue;
            }
            const int saved = errno;
            ::close(fd);
            throw std::system_error(saved, std::generic_category(),
                                    "write " + path);
        }
        buf += written;
        remaining -= static_cast<size_t>(written);
    }

    if (::close(fd) == -1) {
        throw std::system_error(errno, std::generic_category(),
                                "close " + path);
    }
}

} // namespace

CgroupController::CgroupController(pid_t child_pid, const ContainerConfig& config)
    : pid_(child_pid),
      config_(config),
      cgroup_path_(std::string(kCgroupRoot) + "/mini_container_" +
                   std::to_string(child_pid)) {
    // Create the unified cgroup v2 subtree directory for this container.
    if (::mkdir(cgroup_path_.c_str(), 0755) == -1 && errno != EEXIST) {
        throw std::system_error(errno, std::generic_category(),
                                "mkdir " + cgroup_path_);
    }
}

void CgroupController::apply_limits() {
    // Attach the process: writing the PID to cgroup.procs moves it (and its
    // threads) into this cgroup within the unified hierarchy.
    write_cgroup_file(cgroup_path_ + "/cgroup.procs",
                      std::to_string(pid_));

    // Memory ceiling.
    write_cgroup_file(cgroup_path_ + "/memory.max",
                      std::to_string(config_.memory_limit_bytes));
    
    // Disable swap to enforce strict memory ceiling without kernel swap escape.
    try {
        write_cgroup_file(cgroup_path_ + "/memory.swap.max", "0");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[cgroup] warning: failed to disable swap: %s\n", e.what());
    }

    // CPU bandwidth: "<quota> <period>" in microseconds.
    write_cgroup_file(cgroup_path_ + "/cpu.max",
                      std::to_string(config_.cpu_max_quota_us) + " " +
                      std::to_string(config_.cpu_max_period_us));
}

CgroupController::~CgroupController() {
    // RAII cleanup: remove the cgroup subtree directory. A cgroup directory can
    // only be removed once empty (no member processes), which holds after the
    // container has exited. Destructors must not throw, so errors are logged.
    if (::rmdir(cgroup_path_.c_str()) == -1) {
        std::fprintf(stderr, "[cgroup] rmdir %s failed: %s\n",
                     cgroup_path_.c_str(), std::strerror(errno));
    }
}
