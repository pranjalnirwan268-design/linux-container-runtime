#pragma once

class SecurityManager {
public:
    // Drops high-risk Linux capabilities while retaining a minimal set.
    // Runs inside the container child; terminates via _exit(EXIT_FAILURE)
    // on failure.
    static void drop_capabilities();

    // Installs the seccomp BPF filter blocking hazardous syscalls.
    // Runs inside the container child; terminates via _exit(EXIT_FAILURE)
    // on failure.
    static void apply_seccomp_filters();
};
