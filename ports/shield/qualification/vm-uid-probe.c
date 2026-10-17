/* VM-only setuid diagnostic. No arguments, files, fork/exec or hardware IO. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "VM UID diagnostic requires AArch64"
#endif

int main(int argc, char **argv)
{
  uid_t r, e, s, ar, ae, as;
  gid_t gr, ge, gs, agr, age, ags;
  (void)argv;
  if (argc != 1 || close_range(3, ~0u, 0) || getresuid(&r, &e, &s) ||
      getresgid(&gr, &ge, &gs)) return 64;
  int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  if (r != 1001 || e != 0 || s != 0 || gr != 1001 || ge != 1001 ||
      gs != 1001 || nnp != 0) return 64;
  /* Remove every privilege before returning any record to the user process. */
  if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) || setgroups(0, NULL) ||
      setresgid(1001, 1001, 1001) || setresuid(1001, 1001, 1001) ||
      getresuid(&ar, &ae, &as) || getresgid(&agr, &age, &ags) ||
      ar != 1001 || ae != 1001 || as != 1001 ||
      agr != 1001 || age != 1001 || ags != 1001 || getgroups(0, NULL) != 0)
    return 64;
  errno = 0;
  if (setresuid(0, 0, 0) != -1 || errno != EPERM) {
    if (setresuid(1001, 1001, 1001)) return 65;
    return 64;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 64;
  int result = printf("{\"format_version\":1,\"ruid_before\":%lu,\"euid_before\":%lu,"
    "\"suid_before\":%lu,\"rgid_before\":%lu,\"egid_before\":%lu,\"sgid_before\":%lu,"
    "\"nnp_before\":0,\"ruid_after\":1001,\"euid_after\":1001,\"suid_after\":1001,"
    "\"rgid_after\":1001,\"egid_after\":1001,\"sgid_after\":1001,\"nnp_after\":1,"
    "\"supplementary_groups_after\":0,\"root_regain_denied\":true,\"extra_fds_closed\":true}\n",
    (unsigned long)r, (unsigned long)e, (unsigned long)s,
    (unsigned long)gr, (unsigned long)ge, (unsigned long)gs);
  return result > 0 && fflush(stdout) == 0 ? 0 : 65;
}
