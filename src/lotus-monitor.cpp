/*
 * SPDX-FileCopyrightText: 2025 Võ Ngô Hoàng Thành <thanhpy2009@gmail.com>
 * SPDX-FileCopyrightText: 2026 Nguyễn Hoàng Kỳ  <nhktmdzhg@gmail.com>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */
#include "common-executable-path.h"
#include "common-fd-guard.h"
#include "lotus-log.h"
#include "lotus-monitor.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <climits> // IWYU pragma: keep

#if LOTUS_FLATPAK_ADDON
namespace {
    /**
     * @brief Returns the uid the kernel reports for users unmapped in our user namespace.
     */
    uid_t overflowUid() {
        uid_t   uid = 65534;
        FdGuard fd(open("/proc/sys/kernel/overflowuid", O_RDONLY));
        if (fd.isValid()) {
            std::array<char, 16> buf{};
            if (read(fd.get(), buf.data(), buf.size() - 1) > 0) {
                uid = static_cast<uid_t>(strtoul(buf.data(), nullptr, 10));
            }
        }
        return uid;
    }
} // namespace
#endif

bool authenticateMouseSocketPeer(int sock, std::string& out_exe_path) {
    struct ucred cred{};
    socklen_t    credLen = sizeof(cred);

    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &credLen) != 0) {
        LOTUS_ERROR("Failed to get peer credentials: " + std::string(strerror(errno)));
        return false;
    }

#if LOTUS_FLATPAK_ADDON
    // Inside the Flatpak sandbox the host server is outside our pid namespace
    // (pid reads as 0) and its system user is outside our user namespace (uid
    // reads as the overflow uid). Only the user's own uid is mapped, so this
    // accepts system accounts on the host while still rejecting any process
    // running as the user, inside or outside the sandbox.
    if (cred.pid == 0) {
        out_exe_path = "<host process uid=" + std::to_string(cred.uid) + ">";
        return cred.uid != getuid() && cred.uid == overflowUid();
    }
#endif

    std::array<char, 64> procPath{};
    snprintf(procPath.data(), procPath.size(), "/proc/%d/cmdline", cred.pid);

    FdGuard fd(open(procPath.data(), O_RDONLY));
    if (!fd.isValid()) {
        LOTUS_ERROR("Failed to open cmdline: " + std::string(strerror(errno)));
        return false;
    }

    std::array<char, PATH_MAX> exePath{};
    ssize_t                    bytesRead = read(fd.get(), exePath.data(), exePath.size() - 1);

    if (bytesRead <= 0) {
        LOTUS_ERROR("Failed to read cmdline: " + std::string(strerror(errno)));
        return false;
    }

    out_exe_path = exePath.data();

    return isAllowedExecutablePath(exePath.data(), LOTUS_SERVER_EXECUTABLE, LOTUS_ALT_EXECUTABLE_PREFIX);
}
