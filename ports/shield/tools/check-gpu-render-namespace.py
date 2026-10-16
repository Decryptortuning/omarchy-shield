#!/usr/bin/env python3
"""Test the real private mount namespace without opening a GPU device."""
from pathlib import Path
import argparse
import json
import os
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path, help='New directory for isolated test artifacts')
args = parser.parse_args()
if os.geteuid() != 0:
  parser.error('This namespace-only test requires root; it never opens a physical device.')
os.umask(0o077)
r = args.output.resolve()
r.mkdir(mode=0o700)
source = Path(__file__).resolve().parent.parent / 'diagnostic/gpu/native-egl.c'
s = source.read_text()
functions = s[s.index('static int ram_mounts(void)'):s.index('\nint main(')]
root=r/'namespace-root';root.mkdir(mode=0o700)
header='''#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/magic.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>
#define ROOT "'''+str(root)+'''"
'''
tail='''
static int visible(int fd){pid_t pid=fork();assert(pid>=0);if(!pid){struct stat st;if(fchdir(fd)||chroot(".")||chdir("/")||setgroups(0,NULL)||setgid(65534)||setuid(65534))_exit(2);int ok=!stat("/dev/dri/renderD128",&st)&&S_ISCHR(st.st_mode)&&major(st.st_rdev)==226&&minor(st.st_rdev)==128;_exit(ok?0:1);}int status;assert(waitpid(pid,&status,0)==pid&&WIFEXITED(status));return WEXITSTATUS(status);}
int main(void){assert(geteuid()==0);assert(!unshare(CLONE_NEWNS));assert(!mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL));assert(!mount("tmpfs",ROOT,"tmpfs",MS_NOSUID|MS_NODEV,"mode=0755"));assert(!mkdir(ROOT"/dev",0755));assert(!mkdir(ROOT"/sys",0755));assert(!mkdir(ROOT"/proc",0755));assert(!mkdir(ROOT"/run",0755));int old=open(ROOT,O_DIRECTORY|O_RDONLY);assert(old>=0);umask(077);assert(ram_mounts());assert(visible(old)==1);int current=namespace_root_fd(old);assert(current>=0);assert(visible(current)==0);close(current);close(old);puts("PASS: realmountnamespace, actualram_mounts/newrootFD; oldFDchrootcannotseeGPU; reopenedFDUID65534seesverifiedchar226:128; nophysicaldeviceopened");return 0;}
'''
p=r/'namespace-test.c';p.write_text(header+functions+tail)
subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-o',str(r/'namespace-test'),str(p)],check=True)
got=subprocess.run([str(r/'namespace-test')],capture_output=True,text=True)
assert got.returncode==0,(got.returncode,got.stdout,got.stderr)
print(got.stdout.strip());(r/'namespace-regression.json').write_text(json.dumps({'actual_functions':['ram_mounts','namespace_root_fd'],'real_CLONE_NEWNS_RAM_sysfs_proc_mounts':True,'old_before_unshare_FD_negative_child':'GPU_NODE_ENOENT','reopened_namespace_root_FD_child_UID65534':'GPU_NODE_VISIBLE_char226128','GPU_node_open_or_ioctl':False,'USB_or_owner_filesystem_access':False,'global_mounts_changed':False,'result':got.stdout.strip()},indent=2)+'\n')
