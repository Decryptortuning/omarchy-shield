#!/usr/bin/env python3
"""Actual-source baseline and corrected-callback regression; no physical device access."""
from pathlib import Path
import subprocess,signal,json
import argparse
import resource
parser=argparse.ArgumentParser(description="Exercise actual Tegra Mesa callbacks without opening a GPU")
parser.add_argument('--source',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
args=parser.parse_args()
k=args.source.resolve(strict=True)
r=args.output.resolve()
r.mkdir(mode=0o700,parents=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
s=(k/'src/gallium/drivers/tegra/tegra_context.c').read_text()
a=s.index('static void\ntegra_set_device_reset_callback(');b=s.index('\nstatic void',a+1);wrapper=s[a:b]
needle='   if (context->gpu->set_device_reset_callback)\n      context->base.set_device_reset_callback = tegra_set_device_reset_callback;'
assert s.count(needle)==1
st=(k/'src/mesa/state_tracker/st_cb_flush.c').read_text();a=st.index('void\nst_install_device_reset_callback(');b=st.index('\n\nvoid',a+1);install=st[a:b]
header='''#include <assert.h>
#include <stddef.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
struct pipe_device_reset_callback { void (*reset)(void *, int); void *data; };
struct pipe_context { void (*set_device_reset_callback)(struct pipe_context *, const struct pipe_device_reset_callback *); };
struct tegra_context { struct pipe_context base; struct pipe_context *gpu; };
static struct tegra_context *to_tegra_context(struct pipe_context *p){return (struct tegra_context *)p;}
struct st_context { struct pipe_context *pipe; };
static void st_device_reset_callback(void *data,int status){(void)data;(void)status;}
'''
tail='''
static unsigned calls;
static struct pipe_context *expected;
static void available(struct pipe_context *gpu,const struct pipe_device_reset_callback *cb){assert(gpu==expected&&cb&&cb->reset==st_device_reset_callback);calls++;}
static void setup(struct tegra_context *context){REGISTRATION}
int main(void){
  struct pipe_context gpu={0};struct tegra_context tegra={.gpu=&gpu};struct st_context st={.pipe=&tegra.base};
  setup(&tegra);
#ifdef BASELINE
  pid_t child=fork();assert(child>=0);if(!child){assert(!prctl(PR_SET_DUMPABLE,0,0,0,0));st_install_device_reset_callback(&st);_exit(0);}int status;assert(waitpid(child,&status,0)==child);assert(WIFSIGNALED(status)&&WTERMSIG(status)==SIGSEGV);
#else
  assert(tegra.base.set_device_reset_callback==NULL);st_install_device_reset_callback(&st);assert(calls==0);
  expected=&gpu;gpu.set_device_reset_callback=available;setup(&tegra);assert(tegra.base.set_device_reset_callback);st_install_device_reset_callback(&st);assert(calls==1);
#endif
  return 0;
}
'''
results=[]
for baseline in [True,False]:
  name='baseline' if baseline else 'fixed';registration='context->base.set_device_reset_callback = tegra_set_device_reset_callback;' if baseline else needle
  p=r/f'mesa-reset-{name}.c';p.write_text(header+wrapper+install+tail.replace('REGISTRATION',registration))
  cmd=['gcc','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-o',str(r/f'mesa-reset-{name}'),str(p)]
  if baseline:cmd.insert(1,'-DBASELINE')
  subprocess.run(cmd,check=True);subprocess.run([str(r/f'mesa-reset-{name}')],check=True)
  results.append({'actual_tegra_wrapper_and_ST_installer':True,'case':name,'result':'baselineNULLcallbackSIGSEGV reproduced' if baseline else 'absentoptionalcallbackskipped; availablecallbackforwardedexactlyonce'})
(r/'mesa-reset-regression.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))
