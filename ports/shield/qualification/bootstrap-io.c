/* Owned nonblocking result channel for native one-shot helpers. */
#define _GNU_SOURCE
#include "bootstrap-io.h"
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>

/* PID1 supplies /dev/null on stdin/stderr and an owned, nonblocking anonymous
 * pipe on stdout. Never write synchronously to ACM, a terminal or a file. The
 * parent must consume the complete record AND observe exit0 AND independently
 * recheck its own boottime deadline/sample age before accepting this result.
 */
bool sb_standard_fds(void)
{
  for (int fd = 0; fd <= 2; fd++) {
    struct stat info;
    struct statfs filesystem;
    int flags = fcntl(fd, F_GETFL);
    if (fstat(fd, &info) || fstatfs(fd, &filesystem) || flags < 0 ||
        info.st_uid || info.st_gid)
      return false;
    if (fd == 1) {
      if (!S_ISFIFO(info.st_mode) || filesystem.f_type != PIPEFS_MAGIC ||
          (info.st_mode & 0777) != 0600 ||
          (flags & O_ACCMODE) != O_WRONLY || !(flags & O_NONBLOCK))
        return false;
    } else if (!S_ISCHR(info.st_mode) || filesystem.f_type != TMPFS_MAGIC ||
               major(info.st_rdev) != 1 || minor(info.st_rdev) != 3) {
      return false;
    }
  }
  return true;
}

