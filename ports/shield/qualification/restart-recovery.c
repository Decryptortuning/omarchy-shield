/* Static AArch64 recovery helper for the bound qualification receiver.
 * No raw MMIO, partition/BCB writes, shell commands, or fallback reboot here.
 * Exit 64: a guard refused or an input could not be verified.
 * Exit 75: every guard passed, RESTART2("recovery") was attempted and returned.
 * A returned restart never authorizes a plain-reboot fallback.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "Build this probe helper for AArch64 only"
#endif
_Static_assert(sizeof(long) == 8, "AArch64 LP64 syscall ABI required");

enum { GUARD_REFUSED = 64, RESTART_RETURNED = 75 };

static int refuse(const char *reason)
{
    fprintf(stderr, "Recovery restart refused: %s\n", reason);
    return GUARD_REFUSED;
}

/* The final extra-byte read rejects truncation instead of accepting a prefix. */
static int read_file(const char *path, unsigned char *buf, size_t cap, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t used = 0;
    unsigned char extra;
    ssize_t n;

    if (fd < 0)
        return -1;
    while (used < cap) {
        n = read(fd, buf + used, cap - used);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            goto fail;
        if (n == 0) {
            if (close(fd) < 0)
                return -1;
            *len = used;
            return 0;
        }
        used += (size_t)n;
    }
    do {
        n = read(fd, &extra, 1);
    } while (n < 0 && errno == EINTR);
    if (n != 0)
        goto fail;
    if (close(fd) < 0)
        return -1;
    *len = used;
    return 0;
fail:
    close(fd);
    return -1;
}

static int exact_dt(const char *path, const char *expected, size_t expected_len)
{
    unsigned char buf[256];
    size_t len;

    return read_file(path, buf, sizeof(buf), &len) == 0 &&
           len == expected_len && memcmp(buf, expected, len) == 0;
}

/* Exactly one assignment is accepted; conflicting or duplicate values refuse. */
static int exact_assignment(const unsigned char *cmdline, size_t len,
                            const char *key, const char *expected)
{
    const size_t key_len = strlen(key), expected_len = strlen(expected);
    size_t pos = 0, start, count = 0;

    while (pos < len) {
        while (pos < len && isspace(cmdline[pos]))
            pos++;
        start = pos;
        while (pos < len && !isspace(cmdline[pos]))
            pos++;
        if (pos - start >= key_len &&
            memcmp(cmdline + start, key, key_len) == 0) {
            if (pos - start != expected_len ||
                memcmp(cmdline + start, expected, expected_len) != 0)
                return 0;
            count++;
        }
    }
    return count == 1;
}

int main(int argc, char **argv)
{
    static const char compatible[] = "nvidia,p2894-0050-a04\0"
                                     "nvidia,darcy\0"
                                     "nvidia,tegra210";
    static const char model[] = "NVIDIA Shield TV (Darcy A04)";
    static const char stamp[] = "a04-first-ram-probe-v1";
    static const char recovery[] = "recovery";
    unsigned char cmdline[4096];
    size_t len;
    long result;
    int saved_errno;

    (void)argv;
    if (argc != 1)
        return refuse("no arguments are accepted");
    if (getuid() != 0 || geteuid() != 0)
        return refuse("real and effective UID 0 required");
    if (!exact_dt("/proc/device-tree/compatible", compatible, sizeof(compatible)))
        return refuse("exact ordered A04/Darcy/T210 compatible required");
    if (!exact_dt("/proc/device-tree/model", model, sizeof(model)))
        return refuse("exact modern A04 DT model required");
    if (!exact_dt("/proc/device-tree/chosen/shield,first-ram-probe", stamp, sizeof(stamp)))
        return refuse("exact first-probe DT stamp required");
    if (read_file("/proc/cmdline", cmdline, sizeof(cmdline), &len) < 0 ||
        memchr(cmdline, '\0', len) != NULL)
        return refuse("complete, ordinary kernel command line required");
    if (!exact_assignment(cmdline, len, "shield.first-ram-probe=",
                          "shield.first-ram-probe=1"))
        return refuse("exact unique first-probe marker required");
    if (!exact_assignment(cmdline, len, "tegra_smmu.reset_inherited=",
                          "tegra_smmu.reset_inherited=1"))
        return refuse("exact unique inherited-SMMU-reset marker required");

    fprintf(stderr, "Requesting guarded RESTART2(\"recovery\").\n");
    errno = 0;
    result = syscall((long)SYS_reboot,
                     (unsigned long)LINUX_REBOOT_MAGIC1,
                     (unsigned long)LINUX_REBOOT_MAGIC2,
                     (unsigned long)LINUX_REBOOT_CMD_RESTART2,
                     recovery);
    saved_errno = errno;
    fprintf(stderr, "RESTART2 returned %ld, errno=%d (%s); no fallback is authorized.\n",
            result, saved_errno, strerror(saved_errno));
    return RESTART_RETURNED;
}
