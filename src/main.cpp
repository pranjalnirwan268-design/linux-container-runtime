#include "config.hpp"
#include "process.hpp"
#include "cgroup.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include <unistd.h>
#include <sys/wait.h>

namespace {

void print_usage(const char* prog) {
    std::fprintf(stderr,
        "Usage: %s [options] [--] <command> [args...]\n"
        "\n"
        "Options:\n"
        "  --rootfs <path>    Path to the container root filesystem (default ./rootfs)\n"
        "  --hostname <name>  Container hostname (default container-isolated)\n"
        "  --memory <bytes>   Memory limit in bytes (default 104857600 = 100MB)\n"
        "  --cpu-quota <us>   CPU quota in microseconds per period (default 50000)\n"
        "  --cpu-period <us>  CPU period in microseconds (default 100000)\n"
        "  -h, --help         Show this help\n",
        prog);
}

// Parse an unsigned 64-bit value; returns false on malformed input.
bool parse_u64(const char* s, uint64_t& out) {
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(s, &end, 10);
    if (errno != 0 || end == s || (end != nullptr && *end != '\0')) {
        return false;
    }
    out = static_cast<uint64_t>(v);
    return true;
}

} // namespace

int main(int argc, char** argv) {
    ContainerConfig config;
    bool command_set = false;

    int i = 1;
    for (; i < argc; ++i) {
        const std::string a = argv[i];

        if (a == "--") {
            ++i;
            break;
        } else if (a == "-h" || a == "--help") {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        } else if (a == "--rootfs") {
            if (++i >= argc) { print_usage(argv[0]); return EXIT_FAILURE; }
            config.rootfs_path = argv[i];
        } else if (a == "--hostname") {
            if (++i >= argc) { print_usage(argv[0]); return EXIT_FAILURE; }
            config.hostname = argv[i];
        } else if (a == "--memory") {
            if (++i >= argc) { print_usage(argv[0]); return EXIT_FAILURE; }
            if (!parse_u64(argv[i], config.memory_limit_bytes)) {
                std::fprintf(stderr, "Invalid --memory value: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if (a == "--cpu-quota") {
            if (++i >= argc) { print_usage(argv[0]); return EXIT_FAILURE; }
            if (!parse_u64(argv[i], config.cpu_max_quota_us)) {
                std::fprintf(stderr, "Invalid --cpu-quota value: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if (a == "--cpu-period") {
            if (++i >= argc) { print_usage(argv[0]); return EXIT_FAILURE; }
            if (!parse_u64(argv[i], config.cpu_max_period_us)) {
                std::fprintf(stderr, "Invalid --cpu-period value: %s\n", argv[i]);
                return EXIT_FAILURE;
            }
        } else if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "Unknown option: %s\n", a.c_str());
            print_usage(argv[0]);
            return EXIT_FAILURE;
        } else {
            // First positional argument: start of the command.
            break;
        }
    }

    // Remaining argv forms the command + its arguments.
    if (i < argc) {
        std::vector<std::string> cmd;
        for (int j = i; j < argc; ++j) {
            cmd.emplace_back(argv[j]);
        }
        config.command = cmd.front();
        config.args = std::move(cmd);
        command_set = true;
    }

    if (!command_set) {
        // Fall back to the spec defaults (/bin/sh).
        config.command = "/bin/sh";
        config.args = {"/bin/sh"};
    }

    // Runtime requires elevated privileges for namespaces / mounts / cgroups.
    if (geteuid() != 0) {
        std::fprintf(stderr,
            "[main] warning: not running as root; namespace, mount, and "
            "cgroup operations will likely fail.\n");
    }

    // --- Launch the container child -----------------------------------------
    pid_t child = ContainerProcess::launch(config);
    if (child == -1) {
        std::fprintf(stderr, "[main] failed to launch container\n");
        return EXIT_FAILURE;
    }

    const int sync_fd = ContainerProcess::sync_write_fd();

    // --- Apply cgroup v2 limits (host side) ---------------------------------
    // Scoped so the RAII destructor removes the cgroup directory after the
    // container exits (once it is empty).
    int exit_code = EXIT_FAILURE;
    try {
        CgroupController cgroup(child, config);
        cgroup.apply_limits();

        // --- Release the child barrier --------------------------------------
        // The child is blocked on read(); write one byte now that limits are
        // in place, then close so the child never blocks again.
        const char token = 'K';
        ssize_t w;
        do {
            w = write(sync_fd, &token, 1);
        } while (w == -1 && errno == EINTR);
        if (w != 1) {
            std::fprintf(stderr, "[main] failed to signal child: %s\n",
                         std::strerror(errno));
            // Child is still blocked; reap it after closing the pipe to avoid
            // a deadlock (EOF will make read() return 0 -> child_fail).
        }
        if (sync_fd != -1) {
            close(sync_fd);
        }

        // --- Wait for the container to exit ---------------------------------
        int status = 0;
        pid_t waited;
        do {
            waited = waitpid(child, &status, 0);
        } while (waited == -1 && errno == EINTR);

        if (waited == -1) {
            std::fprintf(stderr, "[main] waitpid failed: %s\n",
                         std::strerror(errno));
            exit_code = EXIT_FAILURE;
        } else if (WIFEXITED(status)) {
            exit_code = WEXITSTATUS(status);
            std::fprintf(stderr, "[main] container exited with code %d\n",
                         exit_code);
        } else if (WIFSIGNALED(status)) {
            const int sig = WTERMSIG(status);
            std::fprintf(stderr, "[main] container killed by signal %d (%s)\n",
                         sig, strsignal(sig));
            exit_code = 128 + sig;
        } else {
            std::fprintf(stderr, "[main] container ended abnormally\n");
            exit_code = EXIT_FAILURE;
        }
        // cgroup destructor runs here, removing the (now empty) subtree.
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[main] cgroup setup failed: %s\n", e.what());
        // Best-effort: release the child so it does not hang, then reap it.
        if (sync_fd != -1) {
            close(sync_fd);
        }
        int status = 0;
        waitpid(child, &status, 0);
        return EXIT_FAILURE;
    }

    return exit_code;
}
