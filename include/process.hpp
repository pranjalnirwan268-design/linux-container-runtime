#pragma once
#include "config.hpp"
#include <sys/types.h>

class ContainerProcess {
public:
    // Allocates the child stack, creates the sync pipe, and clones the
    // container child with the required namespace flags. Returns the child PID
    // (in the parent) or -1 on failure.
    static pid_t launch(const ContainerConfig& config);

    // clone() entry point for the container child. Receives a pointer to the
    // internal ChildContext. Never returns on success (execve), otherwise
    // terminates via _exit(EXIT_FAILURE).
    static int child_entry(void* arg);

    // Write end of the synchronization barrier pipe, populated by launch().
    // After the parent has applied cgroup limits it writes a single byte here
    // to release the blocked child, then closes it. Valid only after a
    // successful launch(); -1 otherwise.
    static int sync_write_fd();
};
