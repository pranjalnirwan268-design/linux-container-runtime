#include "security.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>
#include <sys/capability.h>
#include <seccomp.h>

namespace {

[[noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "[security] %s failed: %s\n", what, std::strerror(errno));
    _exit(EXIT_FAILURE);
}

[[noreturn]] void fail_rc(const char* what, int rc) {
    // libseccomp returns negative errno-style codes rather than setting errno.
    std::fprintf(stderr, "[security] %s failed: %s\n", what,
                 std::strerror(rc < 0 ? -rc : rc));
    _exit(EXIT_FAILURE);
}

// Capabilities retained in the container (permitted + effective + inheritable
// cleared beyond this set). Everything else is dropped from all sets.
constexpr cap_value_t kRetained[] = {
    CAP_SETPCAP,
    CAP_MKNOD,
    CAP_AUDIT_WRITE,
    CAP_CHOWN,
    CAP_NET_RAW,
    CAP_DAC_OVERRIDE,
    CAP_FOWNER,
    CAP_FSETID,
    CAP_KILL,
    CAP_SETGID,
    CAP_SETUID,
    CAP_NET_BIND_SERVICE,
};

} // namespace

void SecurityManager::drop_capabilities() {
    // Start from an empty capability set and grant back only the retained caps
    // in all three sets (effective, permitted, inheritable).
    cap_t caps = cap_init();
    if (caps == nullptr) {
        fail("cap_init");
    }

    const int n = static_cast<int>(sizeof(kRetained) / sizeof(kRetained[0]));

    if (cap_set_flag(caps, CAP_EFFECTIVE, n, kRetained, CAP_SET) == -1) {
        cap_free(caps);
        fail("cap_set_flag(CAP_EFFECTIVE)");
    }
    if (cap_set_flag(caps, CAP_PERMITTED, n, kRetained, CAP_SET) == -1) {
        cap_free(caps);
        fail("cap_set_flag(CAP_PERMITTED)");
    }
    if (cap_set_flag(caps, CAP_INHERITABLE, n, kRetained, CAP_SET) == -1) {
        cap_free(caps);
        fail("cap_set_flag(CAP_INHERITABLE)");
    }

    if (cap_set_proc(caps) == -1) {
        cap_free(caps);
        fail("cap_set_proc");
    }

    if (cap_free(caps) == -1) {
        fail("cap_free");
    }
}

void SecurityManager::apply_seccomp_filters() {
    // Default-allow filter; we deny-list the hazardous syscalls with EPERM.
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == nullptr) {
        // seccomp_init returns NULL on failure and does not set errno reliably.
        std::fprintf(stderr, "[security] seccomp_init failed\n");
        _exit(EXIT_FAILURE);
    }

    static const int blocked[] = {
        SCMP_SYS(reboot),
        SCMP_SYS(kexec_load),
        SCMP_SYS(kexec_file_load),
        SCMP_SYS(init_module),
        SCMP_SYS(finit_module),
        SCMP_SYS(delete_module),
        SCMP_SYS(ptrace),
    };

    for (int syscall_nr : blocked) {
        const int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
                                        syscall_nr, 0);
        if (rc != 0) {
            seccomp_release(ctx);
            fail_rc("seccomp_rule_add", rc);
        }
    }

    const int rc = seccomp_load(ctx);
    if (rc != 0) {
        seccomp_release(ctx);
        fail_rc("seccomp_load", rc);
    }

    // The loaded filter persists in the kernel for this process; the context
    // object itself can be released.
    seccomp_release(ctx);
}
