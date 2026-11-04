/* fbstatus: draw a text file on the framebuffer in large type (recovery diagnostic).
 * Usage: fbstatus <textfile> <seconds>. Stops nothing itself; caller stops the UI. */
#include <fcntl.h>
#include <linux/fb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "font8x16.h"
int main(int argc,char**argv){
 if(argc<3)return 2; int fd=open("/dev/graphics/fb0",O_RDWR); if(fd<0)fd=open("/dev/fb0",O_RDWR); if(fd<0)return 3;
 struct fb_var_screeninfo v; struct fb_fix_screeninfo f; if(ioctl(fd,FBIOGET_VSCREENINFO,&v)||ioctl(fd,FBIOGET_FSCREENINFO,&f))return 4;
 int bpp=v.bits_per_pixel/8; if(bpp<2)return 5; size_t len=f.smem_len?f.smem_len:(size_t)f.line_length*v.yres_virtual;
 unsigned char*fb=mmap(0,len,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0); if(fb==MAP_FAILED)return 6;
 (void)ioctl(fd,FBIOBLANK,FB_BLANK_UNBLANK);
 int S=v.xres>=3000?4:(v.xres>=1800?3:2), cw=8*S, ch=16*S, cols=v.xres/cw, rows=v.yres/ch;
 char*buf=calloc(1,65536); FILE*in=fopen(argv[1],"r"); size_t n=in?fread(buf,1,65535,in):0; if(in)fclose(in);
 unsigned pages=v.yres_virtual/v.yres; if(pages<1)pages=1; if((size_t)pages*v.yres*f.line_length>len)pages=1;
 for(unsigned pg=0;pg<pages;pg++){unsigned char*base=fb+(size_t)pg*v.yres*f.line_length;
 for(unsigned y=0;y<v.yres;y++)memset(base+(size_t)y*f.line_length,0,(size_t)v.xres*bpp);
 int r=0,c=0;
 for(size_t i=0;i<n&&r<rows;i++){unsigned char ch_=buf[i]; if(ch_=='\n'){r++;c=0;continue;} if(c>=cols){r++;c=0;if(r>=rows)break;}
  const unsigned char*g=font8x16+ch_*16;
  for(int gy=0;gy<16;gy++)for(int gx=0;gx<8;gx++)if(g[gy]&(0x80>>gx))
   for(int sy=0;sy<S;sy++){unsigned char*p=base+(size_t)(r*ch+gy*S+sy)*f.line_length+(size_t)(c*cw+gx*S)*bpp;
    for(int sx=0;sx<S;sx++){ if(bpp==4){p[0]=p[1]=p[2]=255;p[3]=255;} else {p[0]=p[1]=255;} p+=bpp; } }
  c++;}
 }
 msync(fb,len,MS_SYNC); v.yoffset=0; v.xoffset=0; v.activate=FB_ACTIVATE_NOW|FB_ACTIVATE_FORCE; (void)ioctl(fd,FBIOPAN_DISPLAY,&v); (void)ioctl(fd,FBIOBLANK,FB_BLANK_UNBLANK);
 fprintf(stderr,"fbstatus %ux%u bpp%d pages%u line%u\n",v.xres,v.yres,bpp*8,pages,f.line_length);
 sleep((unsigned)atoi(argv[2])); return 0;
}
