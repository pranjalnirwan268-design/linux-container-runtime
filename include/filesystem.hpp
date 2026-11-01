#pragma once
#include <filesystem>

class ContainerFilesystem {
public:
    // Executes the full pivot_root containment sequence against an already
    // canonicalized rootfs path. Intended to run inside the container child.
    // On any syscall failure it writes to stderr and calls _exit(EXIT_FAILURE).
    static void setup(const std::filesystem::path& rootfs_path);
};
