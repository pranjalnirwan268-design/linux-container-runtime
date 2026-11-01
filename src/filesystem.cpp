#include "filesystem.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>

#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>

namespace {

// Report a failing syscall and terminate the child without flushing the
// parent's stdio buffers. No heap allocation occurs on this path.
[[noreturn]] void fail(const char* what) {
    // fprintf to stderr is async-signal-unsafe in theory, but acceptable here:
    // this runs in the cloned child before execve and we are aborting anyway.
    std::fprintf(stderr, "[filesystem] %s failed: %s\n", what, std::strerror(errno));
    _exit(EXIT_FAILURE);
}

} // namespace

void ContainerFilesystem::setup(const std::filesystem::path& rootfs_path) {
    // The caller passes an already-canonicalized absolute path. Hold onto the
    // string storage so the c_str() pointers stay valid for the whole routine.
    const std::string abs_rootfs = rootfs_path.string();
    const std::string old_root = abs_rootfs + "/.old_root";

    // 1. Mount tree privacy: make the whole tree private & recursive so that
    //    subsequent mount operations do not propagate back to the host.
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) == -1) {
        fail("mount(MS_REC|MS_PRIVATE on /)");
    }

    // 2. Self bind-mount: pivot_root requires new_root to be a mount point.
    if (mount(abs_rootfs.c_str(), abs_rootfs.c_str(), nullptr,
              MS_BIND | MS_REC, nullptr) == -1) {
        fail("mount(MS_BIND|MS_REC rootfs)");
    }

    // 3. Old root directory: create <rootfs>/.old_root to receive the old tree.
    if (mkdir(old_root.c_str(), 0700) == -1 && errno != EEXIST) {
        fail("mkdir(.old_root)");
    }

    // 4. Pivot syscall: swap the root. Use the raw syscall; glibc has no
    //    pivot_root wrapper.
    if (syscall(SYS_pivot_root, abs_rootfs.c_str(), old_root.c_str()) == -1) {
        fail("pivot_root");
    }

    // 5. Change directory into the new root.
    if (chdir("/") == -1) {
        fail("chdir(/)");
    }

    // 6. Virtual filesystem mounts.
    //    /proc
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, nullptr) == -1) {
        fail("mount(/proc)");
    }
    //    /sys (read-only)
    if (mount("sysfs", "/sys", "sysfs",
              MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, nullptr) == -1) {
        fail("mount(/sys)");
    }
    //    /dev (tmpfs)
    if (mount("tmpfs", "/dev", "tmpfs",
              MS_NOSUID | MS_STRICTATIME, "mode=755") == -1) {
        fail("mount(/dev)");
    }

    // 7. Cleanup: detach and remove the old root.
    if (umount2("/.old_root", MNT_DETACH) == -1) {
        fail("umount2(/.old_root)");
    }
    if (rmdir("/.old_root") == -1) {
        fail("rmdir(/.old_root)");
    }
}
