#!/usr/bin/env python3
"""Actual-source baseline and corrected-callback regression; no physical device access."""
from pathlib import Path
import subprocess,json
import argparse
import resource
parser=argparse.ArgumentParser(description="Exercise actual Tegra Mesa callbacks without opening a GPU")
parser.add_argument('--source',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--build',required=True,type=Path,help='Mesa build with generated format headers')
args=parser.parse_args()
k=args.source.resolve(strict=True)
r=args.output.resolve()
r.mkdir(mode=0o700,parents=True)
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
fixed=(k/'src/gallium/drivers/tegra/tegra_context.c').read_text()
baseline=subprocess.check_output(['git','show','HEAD:src/gallium/drivers/tegra/tegra_context.c'],cwd=k,text=True)
def functions(source):
  result=''
  for name in ['tegra_set_framebuffer_state','tegra_clear_render_target','tegra_clear_depth_stencil','tegra_clear']:
    a=source.index('static void\n'+name+'(');b=source.index('\nstatic ',a+1);result+=source[a:b]+'\n'
  return result
header='''#include <assert.h>
#include <string.h>
#include "pipe/p_context.h"
#include "tegra_resource.h"
struct tegra_context {struct pipe_context base;struct pipe_context *gpu;};
static struct tegra_context *to_tegra_context(struct pipe_context *p){return (struct tegra_context *)p;}
'''
tail='''
static const struct pipe_scissor_state *seen_scissor;
static void scoped_clear(struct pipe_context *gpu,unsigned buffers,uint32_t color_mask,uint8_t stencil_mask,const struct pipe_scissor_state *scissor,const union pipe_color_union *color,double depth,unsigned stencil){(void)gpu;(void)color;assert(buffers==3&&color_mask==7&&stencil_mask==15&&depth==0.5&&stencil==9);seen_scissor=scissor;}
static struct pipe_framebuffer_state seen;
static struct pipe_resource *surface_texture;
static unsigned surface_calls;
static void framebuffer(struct pipe_context *gpu,const struct pipe_framebuffer_state *fb){(void)gpu;seen=*fb;}
static void color(struct pipe_context *gpu,struct pipe_surface *dst,const union pipe_color_union *value,unsigned x,unsigned y,unsigned w,unsigned h,bool cond){(void)gpu;assert(x==2&&y==3&&w==4&&h==5&&cond&&value->ui[0]==123);surface_texture=dst->texture;assert(dst->level==2&&dst->first_layer==1&&dst->last_layer==3);surface_calls++;}
static void depth(struct pipe_context *gpu,struct pipe_surface *dst,unsigned flags,double d,unsigned stencil,unsigned x,unsigned y,unsigned w,unsigned h,bool cond){(void)gpu;assert(flags==3&&d==0.5&&stencil==7&&x==2&&y==3&&w==4&&h==5&&cond);surface_texture=dst->texture;assert(dst->level==2&&dst->first_layer==1&&dst->last_layer==3);surface_calls++;}
int main(void){
  struct pipe_context gpu={.set_framebuffer_state=framebuffer,.clear_render_target=color,.clear_depth_stencil=depth,.clear=scoped_clear};struct tegra_context ctx={.gpu=&gpu};
  struct pipe_resource underlying[4]={{0}};struct tegra_resource wrapped[4]={0};for(unsigned i=0;i<4;i++)wrapped[i].gpu=&underlying[i];
  struct pipe_framebuffer_state fb={.width=1280,.height=720,.layers=4,.samples=2,.nr_cbufs=3,.viewmask=3,.pls_enabled=true,.cbufs={{.texture=&wrapped[0].base,.level=2},{0},{.texture=&wrapped[1].base,.level=3}},.zsbuf={.texture=&wrapped[2].base,.level=4},.resolve=&wrapped[3].base};
  struct pipe_framebuffer_state original=fb;tegra_set_framebuffer_state(&ctx.base,&fb);assert(!memcmp(&original,&fb,sizeof(fb)));
struct pipe_scissor_state scissor={.minx=1,.miny=2,.maxx=3,.maxy=4};tegra_clear(&ctx.base,3,7,15,&scissor,NULL,0.5,9);
#ifdef BASELINE
  assert(seen_scissor==NULL);assert(seen.cbufs[0].texture==&wrapped[0].base&&seen.cbufs[0].texture!=&underlying[0]);return 0;
#else
  assert(seen_scissor==&scissor);tegra_clear(&ctx.base,3,7,15,NULL,NULL,0.5,9);assert(!seen_scissor);
  assert(seen.width==1280&&seen.height==720&&seen.layers==4&&seen.samples==2&&seen.viewmask==3&&seen.pls_enabled);
  assert(seen.cbufs[0].texture==&underlying[0]&&!seen.cbufs[1].texture&&seen.cbufs[2].texture==&underlying[1]);assert(seen.zsbuf.texture==&underlying[2]&&seen.resolve==&underlying[3]);assert(seen.cbufs[0].level==2&&seen.zsbuf.level==4);
  struct pipe_framebuffer_state empty={0};tegra_set_framebuffer_state(&ctx.base,&empty);assert(!seen.nr_cbufs&&!seen.zsbuf.texture&&!seen.resolve);
  struct pipe_surface surface={.texture=&wrapped[0].base,.level=2,.first_layer=1,.last_layer=3},before=surface;union pipe_color_union value={.ui={123}};
  tegra_clear_render_target(&ctx.base,&surface,&value,2,3,4,5,true);assert(surface_texture==&underlying[0]);assert(!memcmp(&surface,&before,sizeof(surface)));
  tegra_clear_depth_stencil(&ctx.base,&surface,3,0.5,7,2,3,4,5,true);assert(surface_texture==&underlying[0]&&surface_calls==2);assert(!memcmp(&surface,&before,sizeof(surface)));
  return 0;
#endif
}
'''
for is_baseline,s in [(True,baseline),(False,fixed)]:
  name='baseline' if is_baseline else 'fixed';p=r/f'mesa-surface-{name}.c'
  h=header
  if is_baseline:
    h+='struct tegra_surface {struct pipe_surface base;struct pipe_surface *gpu;};\nstatic struct tegra_surface *to_tegra_surface(struct pipe_surface *p){return (struct tegra_surface *)p;}\n'
  p.write_text(h+functions(s)+tail)
  cmd=['gcc','-std=c11','-DHAVE_ENDIAN_H=1','-D_GNU_SOURCE','-Wno-missing-braces','-I'+str(args.build.resolve(strict=True)/'src'),'-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-Wno-unused-parameter','-I'+str(k/'src'),'-I'+str(k/'include'),'-I'+str(k/'src/gallium/include'),'-I'+str(k/'src/gallium/drivers/tegra'),'-o',str(r/f'mesa-surface-{name}'),str(p)]
  if is_baseline:cmd.insert(1,'-DBASELINE')
  subprocess.run(cmd,check=True);subprocess.run([str(r/f'mesa-surface-{name}')],check=True)
report={'actual_Mesa_pipe_structs_and_actual_four_Tegra_callbacks':True,'baseline_passes_wrapped_resource_to_Nouveau':'reproduced','fixed':'color/depth/resolve unwrapped; NULLholes preserved; metadata and callerconstinputs preserved; scissorrect forwarded/nullpreserved; currentplainpipe_surface clearcolor/depth forwarded correctly','hardware_claim':False}
(r/'mesa-surface-regression.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
