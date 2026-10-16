#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define ROOT "/run/first-ram-probe/owner-root"
static int exact(const char *path,const char *expected,size_t length) {
  char data[256];int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 0;
  ssize_t n=read(fd,data,sizeof(data));close(fd);return n==(ssize_t)length && !memcmp(data,expected,length);
}
static int mount_guard(void) {
  FILE *f=fopen("/proc/mounts","re");char source[256],point[256],type[64],options[2048],csv[2050];int found=0;if(!f)return 0;
  while(fscanf(f,"%255s %255s %63s %2047s %*d %*d",source,point,type,options)==4) {
    if(strcmp(source,"/dev/sda1")||strcmp(point,ROOT)||strcmp(type,"btrfs"))continue;
    snprintf(csv,sizeof(csv),",%s,",options);if(strstr(csv,",ro,")&&strstr(csv,",rescue=nologreplay,"))found++;
  }
  fclose(f);return found==1;
}
static double clock_seconds(void) {struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;return t.tv_sec+t.tv_nsec/1e9;}
static int ram_mounts(void) {
  if(unshare(CLONE_NEWNS)||mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))return 0;
  if(mount("tmpfs",ROOT"/dev","tmpfs",MS_NOSUID|MS_NOEXEC,"mode=0755"))return 0;
  if(mkdir(ROOT"/dev/dri",0755)||chmod(ROOT"/dev/dri",0755)||mknod(ROOT"/dev/null",S_IFCHR|0666,makedev(1,3))||chmod(ROOT"/dev/null",0666)||mknod(ROOT"/dev/dri/renderD128",S_IFCHR|0600,makedev(226,128))||chown(ROOT"/dev/dri/renderD128",65534,65534))return 0;
  if(mount("sysfs",ROOT"/sys","sysfs",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||mount("proc",ROOT"/proc","proc",MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL)||mount("tmpfs",ROOT"/run","tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"mode=0755"))return 0;
  if(mkdir(ROOT"/run/egl",0700)||chown(ROOT"/run/egl",65534,65534))return 0;
  return 1;
}
/* File descriptors opened before unshare still refer to the old mount tree. */
static int namespace_root_fd(int old_rootfd) {
  struct stat before,after;struct statfs fs;
  if(fstat(old_rootfd,&before))return -1;
  int rootfd=open(ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
  if(rootfd<0)return -1;
  if(fstat(rootfd,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino){close(rootfd);return -1;}
  const char *dirs[]={"dev","sys","proc","run"};
  const long expected[]={TMPFS_MAGIC,SYSFS_MAGIC,PROC_SUPER_MAGIC,TMPFS_MAGIC};
  for(unsigned int i=0;i<4;i++){
    int fd=openat(rootfd,dirs[i],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0){close(rootfd);return -1;}
    int bad=fstatfs(fd,&fs)||fs.f_type!=expected[i];close(fd);
    if(bad){close(rootfd);return -1;}
  }
  if(fstatat(rootfd,"dev/dri/renderD128",&after,AT_SYMLINK_NOFOLLOW)||!S_ISCHR(after.st_mode)||major(after.st_rdev)!=226||minor(after.st_rdev)!=128||after.st_uid!=65534){close(rootfd);return -1;}
  return rootfd;
}

int main(int argc,char **argv) {
  (void)argv;struct utsname u;struct statfs fs;struct stat st;int ro=0,rootfd,fd,elf;char gpu[PATH_MAX],render[PATH_MAX],driver[256];
  setvbuf(stdout,NULL,_IONBF,0);
  if(argc!=1 || geteuid()!=0 || uname(&u)||strcmp(u.release,"7.1.0-shield-bringup"))return 64;
  if(!exact("/proc/device-tree/model","NVIDIA Shield TV (Darcy A04)",sizeof("NVIDIA Shield TV (Darcy A04)"))||!exact("/proc/device-tree/chosen/shield,first-ram-probe","a04-first-ram-probe-v1",sizeof("a04-first-ram-probe-v1"))||!exact("/run/first-ram-probe/gpu-ready","NOUVEAU_RENDER_226_128_V1\n",strlen("NOUVEAU_RENDER_226_128_V1\n")))return 64;
  double start=clock_seconds();if(start<0||start>=16||!mount_guard())return 64;
  rootfd=open(ROOT,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(rootfd<0||fstatfs(rootfd,&fs)||fs.f_type!=BTRFS_SUPER_MAGIC||!(fs.f_flags&ST_RDONLY))return 64;
  const char *dirs[]={"dev","sys","proc","run"};for(unsigned int i=0;i<4;i++){fd=openat(rootfd,dirs[i],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return 64;close(fd);}
  fd=open("/dev/sda1",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0||ioctl(fd,BLKROGET,&ro)||ro!=1)return 64;close(fd);
  if(!realpath("/sys/bus/platform/devices/57000000.gpu",gpu)||!realpath("/sys/class/drm/renderD128/device",render)||strcmp(gpu,render))return 64;
  ssize_t n=readlink("/sys/bus/platform/devices/57000000.gpu/driver",driver,sizeof(driver)-1);if(n<0)return 64;driver[n]=0;char *base=strrchr(driver,'/');if(!base||strcmp(base+1,"nouveau"))return 64;
  fd=open("/dev/dri/renderD128",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0||fstat(fd,&st)||!S_ISCHR(st.st_mode)||major(st.st_rdev)!=226||minor(st.st_rdev)!=128)return 64;close(fd);
  elf=open("/sbin/shield-egl-render",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(elf<0||fstat(elf,&st)||!S_ISREG(st.st_mode)||(st.st_mode&0022))return 64;
  if(!ram_mounts()){printf("GPU_RENDER namespace-setup failed errno=%d\n",errno);return 76;}
  int newroot=namespace_root_fd(rootfd);close(rootfd);rootfd=newroot;
  if(rootfd<0){printf("GPU_RENDER namespace-root view validation failed errno=%d\n",errno);return 76;}
  printf("GPU_RENDER namespace-root RAMdev/sys/proc/run views verified\n");
  printf("GPU_RENDER launcher RO-root=1 block-RO=1 isolated-RAM-dev-run=1 sys-proc-RO=1 limit_seconds=9\n");
  pid_t child=fork();if(child<0)return 125;
  if(!child) {
    char *args[]={"shield-egl-render",NULL};char *env[]={"LC_ALL=C","PATH=/usr/bin:/bin","HOME=/nonexistent","XDG_RUNTIME_DIR=/run/egl","XDG_CACHE_HOME=/run/egl/cache","MESA_SHADER_CACHE_DISABLE=true","EGL_LOG_LEVEL=debug",NULL};
    if(setpgid(0,0)||fchdir(rootfd)||chroot(".")||chdir("/"))_exit(126);close(rootfd);
    if(setgroups(0,NULL)||setgid(65534)||setuid(65534)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(126);
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};struct __user_cap_data_struct caps[2]={{0}};
    if(syscall(SYS_capget,&h,caps)||getuid()!=65534||getgid()!=65534||caps[0].effective||caps[1].effective||caps[0].permitted||caps[1].permitted||caps[0].inheritable||caps[1].inheritable)_exit(126);
    execveat(elf,"",args,env,AT_EMPTY_PATH);printf("GPU_RENDER execveat failed errno=%d\n",errno);_exit(127);
  }
  close(elf);close(rootfd);(void)setpgid(child,child);double deadline=clock_seconds()+9;int status=0;
  for(;;){pid_t done=waitpid(child,&status,WNOHANG);if(done==child){int result=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);printf("GPU_RENDER launcher_child_status=%d\n",result);return result;}if(done<0&&errno!=EINTR)return 125;
    double now=clock_seconds();if(now<0||now>=deadline){if(getpgid(child)==child)(void)kill(-child,SIGKILL);else(void)kill(child,SIGKILL);(void)waitpid(child,&status,WNOHANG);printf("GPU_RENDER launcher_child_status=124 deadline\n");return 124;}
    struct timespec pause={0,10000000};nanosleep(&pause,NULL);
  }
}
