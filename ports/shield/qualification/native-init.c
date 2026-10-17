/* Fixed initial-RAM setup, then exec the sole Python PID1 supervisor.
 * Source preparation only: capsule source closure, link/build/readback and
 * VM qualification must pass before use. No USB/media mount, watchdog open,
 * firmware/register override, fallback reboot or retry exists here.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "Native bootstrap must be built for AArch64"
#endif
_Static_assert(sizeof(long) == 8, "LP64 native bootstrap required");

static char *const environment[] = {
  "PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/root", NULL
};

static void refuse(void)
{
  /* Keep PID1 alive. The pre-existing finite kernel/hardware policy retains
   * ownership; a failed bootstrap must never fabricate a recovery result. */
  for (;;) pause();
}

static void budget(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_BOOTTIME, &value) || value.tv_sec < 0 || value.tv_sec >= 25)
    refuse();
}

static void directory(const char *path, mode_t mode)
{
  struct stat info;
  if (mkdir(path, mode) && errno != EEXIST) refuse();
  if (lstat(path, &info) || !S_ISDIR(info.st_mode) || info.st_uid || info.st_gid ||
      (info.st_mode & 07777) != mode) refuse();
}

static void mounted(const char *source, const char *target, const char *type,
                    unsigned long flags, const char *options)
{
  budget();
  if (mount(source, target, type, flags, options)) refuse();
  budget();
}

static void child(char *const arguments[])
{
  budget();
  pid_t pid = fork();
  if (pid < 0) refuse();
  if (!pid) {
    if (syscall(SYS_close_range, 3u, ~0u, 0u)) _exit(70);
    execve("/bin/busybox", arguments, environment);
    _exit(70);
  }
  int status;
  pid_t result;
  do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
  if (result != pid || !WIFEXITED(status) || WEXITSTATUS(status)) refuse();
  budget();
}

int main(int argc, char **argv)
{
  (void)argv;
  if (getpid() != 1) return 64;
  if (argc != 1 || getuid() || geteuid() || getgid() || getegid()) refuse();
  umask(0);
  struct sigaction action = { .sa_handler = SIG_DFL };
  sigemptyset(&action.sa_mask);
  sigset_t mask;
  sigemptyset(&mask);
  if (sigaction(SIGCHLD, &action, NULL) || sigprocmask(SIG_SETMASK, &mask, NULL)) refuse();
  budget();
  directory("/proc", 0755);
  directory("/sys", 0755);
  directory("/dev", 0755);
  directory("/run", 0755);
  mounted("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  mounted("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  mounted("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755");
  mounted("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755");
  int null = open("/dev/null", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
  struct stat info;
  if (null < 0 || fstat(null, &info) || !S_ISCHR(info.st_mode) || info.st_uid || info.st_gid ||
      info.st_rdev != makedev(1, 3)) refuse();
  for (int fd = 0; fd < 3; fd++) {
    if (dup2(null, fd) != fd || fcntl(fd, F_SETFD, 0)) refuse();
  }
  if (null > 2) close(null);
  if (syscall(SYS_close_range, 3u, ~0u, 0u)) refuse();
  directory("/dev/pts", 0755);
  directory("/dev/shm", 01777);
  mounted("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, "mode=0620,ptmxmode=0666,gid=5");
  mounted("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");
  directory("/sys/fs/cgroup", 0755);
  mounted("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  directory("/sys/kernel/config", 0755);
  mounted("configfs", "/sys/kernel/config", "configfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
  directory("/run/shield-native", 0700);
  char *copy[] = { "busybox", "cp", "-a", "/usr/lib/shield-maintenance/native-seed/.",
                   "/run/shield-native/", NULL };
  child(copy);
  const char *modules[] = {
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/libcomposite.ko",
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/function/u_serial.ko",
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/function/usb_f_acm.ko",
    "/usr/lib/modules/7.1.0-shield-bringup/kernel/drivers/usb/gadget/udc/tegra-xudc.ko"
  };
  for (unsigned index = 0; index < sizeof(modules) / sizeof(modules[0]); index++) {
    char *arguments[] = { "busybox", "insmod", (char *)modules[index], NULL };
    child(arguments);
  }
  /* Every bootstrap child has an actual positive wait, then require ECHILD.
   * A process enumeration or empty WNOHANG tick cannot substitute for this. */
  int status;
  errno = 0;
  if (waitpid(-1, &status, WNOHANG | 0x40000000) != -1 || errno != ECHILD) refuse();
  budget();
  umask(0077);
  char *supervisor[] = { "/usr/bin/python3.14", "-I", "-S", "-B",
    "/run/shield-native/runtime/native-boot.py", "--run", NULL };
  execve(supervisor[0], supervisor, environment);
  refuse();
}
