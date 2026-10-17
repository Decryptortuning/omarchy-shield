/* VM-only PID1 root handoff; no reboot, MMIO, partition or argument API. */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>
#if !defined(__aarch64__)
#error "AArch64 only"
#endif
static int refuse(const char *phase, int code)
{
  fprintf(stderr, "SHIELD_SYSTEMD_VM_INIT_FAIL phase=%s errno=%d\n", phase, errno);
  return code;
}
static int exact(const char *path, const char *expected, size_t bytes)
{
  char data[8192];
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  ssize_t count = read(fd, data, sizeof(data));
  close(fd);
  return count == (ssize_t)bytes && !memcmp(data, expected, bytes);
}
static int marker(void)
{
  char data[8192], *save = NULL;
  int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  ssize_t count = read(fd, data, sizeof(data) - 1);
  close(fd);
  if (count <= 0 || count >= (ssize_t)sizeof(data) - 1 || memchr(data, 0, (size_t)count)) return 0;
  data[count] = 0;
  unsigned found = 0;
  for (char *p = strtok_r(data, " \t\n", &save); p; p = strtok_r(NULL, " \t\n", &save)) {
    if (!strncmp(p, "shield.first-ram-probe=", 23) || !strncmp(p, "shield.guardian=", 16)) return 0;
    if (!strncmp(p, "shield.systemd-vm=", 18)) {
      if (strcmp(p, "shield.systemd-vm=1")) return 0;
      found++;
    }
  }
  return found == 1;
}
int main(int argc, char **argv)
{
  (void)argv;
  struct statfs fs;
  if (argc != 1 || getpid() != 1 || getuid() || geteuid() || getgid() || getegid() ||
      !exact("/proc/device-tree/compatible", "linux,dummy-virt", sizeof("linux,dummy-virt")) ||
      !marker() || statfs("/newroot", &fs) || fs.f_type != BTRFS_SUPER_MAGIC) return refuse("admission", 64);
  static const char *dirs[] = {"dev", "proc", "sys", "run"};
  for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    char from[32], to[64];
    snprintf(from, sizeof(from), "/%s", dirs[i]);
    snprintf(to, sizeof(to), "/newroot/%s", dirs[i]);
    struct stat info;
    if (lstat(to, &info) || !S_ISDIR(info.st_mode) || info.st_uid || info.st_gid ||
        mount(from, to, NULL, MS_MOVE, NULL)) return refuse(dirs[i], 65);
  }
  if (chdir("/newroot") || mount("/newroot", "/", NULL, MS_MOVE, NULL) || chroot(".") || chdir("/"))
    return refuse("root-move", 66);
  char *const arguments[] = {"/usr/lib/systemd/systemd", NULL};
  char *const environment[] = {"PATH=/usr/bin:/bin", "HOME=/", "LANG=C", NULL};
  execve(arguments[0], arguments, environment);
  return refuse("systemd-exec", 67);
}
