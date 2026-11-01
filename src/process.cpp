#include "process.hpp"
#include "filesystem.hpp"
#include "security.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <string>
#include <vector>

#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>

namespace {

constexpr size_t kStackSize = 1024 * 1024; // 1MB

// Everything the child needs is pre-computed in the parent and referenced via
// stable pointers so that the child performs NO heap allocation between clone()
// and execve(). The vectors/strings below outlive the child because launch()
// blocks in the caller until waitpid() returns.
struct ChildContext {
    // Canonicalized absolute rootfs path (storage owned here).
    std::string abs_rootfs;
    std::string hostname;

    // Null-terminated argv/envp arrays. The backing strings live in the
    // owning vectors; the pointer arrays are what execve consumes.
    std::vector<std::string> arg_storage;
    std::vector<char*> argv;
    std::vector<char*> envp;

    int sync_read_fd = -1; // child reads the barrier byte from here
};

[[noreturn]] void child_fail(const char* what) {
    std::fprintf(stderr, "[process:child] %s failed: %s\n", what,
                 std::strerror(errno));
    _exit(EXIT_FAILURE);
}

// Write end of the sync barrier pipe, handed off from launch() to main().
int g_sync_write_fd = -1;

} // namespace

int ContainerProcess::sync_write_fd() {
    return g_sync_write_fd;
}

int ContainerProcess::child_entry(void* arg) {
    auto* ctx = static_cast<ChildContext*>(arg);

    // --- Synchronization barrier --------------------------------------------
    // Block until the parent finishes cgroup v2 setup and writes a byte.
    char token = 0;
    ssize_t r;
    do {
        r = read(ctx->sync_read_fd, &token, 1);
    } while (r == -1 && errno == EINTR);
    if (r != 1) {
        child_fail("read(sync barrier)");
    }
    if (close(ctx->sync_read_fd) == -1) {
        child_fail("close(sync_read_fd)");
    }

    // --- Hostname -----------------------------------------------------------
    if (sethostname(ctx->hostname.c_str(), ctx->hostname.size()) == -1) {
        child_fail("sethostname");
    }

    // --- Filesystem isolation (pivot_root sequence) -------------------------
    // ContainerFilesystem::setup terminates the child itself on failure.
    ContainerFilesystem::setup(ctx->abs_rootfs);

    // --- Security hardening -------------------------------------------------
    // Drop capabilities before applying seccomp so CAP_SETPCAP is available
    // while still needed; seccomp is the final, irreversible lockdown.
    SecurityManager::drop_capabilities();
    SecurityManager::apply_seccomp_filters();

    // --- Hand-off -----------------------------------------------------------
    // No heap allocation: argv/envp pointer arrays were built in the parent.
    execve(ctx->argv[0], ctx->argv.data(), ctx->envp.data());

    // execve only returns on failure.
    child_fail("execve");
}

pid_t ContainerProcess::launch(const ContainerConfig& config) {
    // ChildContext is heap-allocated in the PARENT (allowed) and intentionally
    // leaked for the lifetime of the container: its storage must remain valid
    // for the child until execve. The parent reclaims nothing because the
    // process tree is short-lived and main() waitpid()s before returning.
    auto* ctx = new ChildContext();

    // Resolve an absolute canonical rootfs path on the host (steering rule:
    // never pass relative paths to mount/pivot_root).
    std::error_code ec;
    std::filesystem::path canonical_rootfs =
        std::filesystem::canonical(config.rootfs_path, ec);
    if (ec) {
        std::fprintf(stderr, "[process] canonical(%s) failed: %s\n",
                     config.rootfs_path.c_str(), ec.message().c_str());
        delete ctx;
        return -1;
    }
    ctx->abs_rootfs = canonical_rootfs.string();
    ctx->hostname = config.hostname;

    // Build argv backing storage then the pointer array.
    ctx->arg_storage = config.args;
    ctx->argv.reserve(ctx->arg_storage.size() + 1);
    for (auto& s : ctx->arg_storage) {
        ctx->argv.push_back(s.data());
    }
    ctx->argv.push_back(nullptr);

    // Minimal environment for the containerized process.
    static char path_env[] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    static char term_env[] = "TERM=xterm";
    ctx->envp.push_back(path_env);
    ctx->envp.push_back(term_env);
    ctx->envp.push_back(nullptr);

    // --- Synchronization pipe ----------------------------------------------
    int pipe_fds[2];
    if (pipe2(pipe_fds, O_CLOEXEC) == -1) {
        std::fprintf(stderr, "[process] pipe2 failed: %s\n",
                     std::strerror(errno));
        delete ctx;
        return -1;
    }
    ctx->sync_read_fd = pipe_fds[0];

    // --- Stack allocation ---------------------------------------------------
    void* stack_base = mmap(nullptr, kStackSize, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (stack_base == MAP_FAILED) {
        std::fprintf(stderr, "[process] mmap(stack) failed: %s\n",
                     std::strerror(errno));
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        delete ctx;
        return -1;
    }
    // Stack grows downward on x86_64: hand clone the top of the region.
    char* stack_top = static_cast<char*>(stack_base) + kStackSize;

    // --- Clone --------------------------------------------------------------
    const int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
                      CLONE_NEWIPC | SIGCHLD;

    pid_t child = clone(&ContainerProcess::child_entry, stack_top, flags, ctx);
    if (child == -1) {
        std::fprintf(stderr, "[process] clone failed: %s\n",
                     std::strerror(errno));
        munmap(stack_base, kStackSize);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        delete ctx;
        return -1;
    }

    // The parent keeps the write end to release the child after cgroup setup.
    // Close the parent's copy of the read end: the child holds its own
    // duplicated descriptor (clone copies the fd table; CLONE_VM is not set),
    // so this does not affect the child's read end.
    close(pipe_fds[0]);

    // Hand the write end to main() via the accessor. main() writes a byte here
    // once cgroup limits are applied, releasing the child's read() barrier.
    g_sync_write_fd = pipe_fds[1];

    return child;
}
