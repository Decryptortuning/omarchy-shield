#define _GNU_SOURCE
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES2/gl2.h>
#include <dlfcn.h>
#include <gbm.h>
#include <xf86drm.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#define EGL_FUNCTIONS(X) X(eglGetProcAddress) X(eglGetError) X(eglInitialize) X(eglBindAPI) X(eglChooseConfig) X(eglCreateContext) X(eglCreatePbufferSurface) X(eglMakeCurrent) X(eglQueryString) X(eglDestroySurface) X(eglDestroyContext) X(eglTerminate)
#define GL_FUNCTIONS(X) X(glGetString) X(glGetError) X(glGenTextures) X(glBindTexture) X(glTexParameteri) X(glTexImage2D) X(glDeleteTextures) X(glGenFramebuffers) X(glBindFramebuffer) X(glFramebufferTexture2D) X(glCheckFramebufferStatus) X(glDeleteFramebuffers) X(glGenBuffers) X(glBindBuffer) X(glBufferData) X(glDeleteBuffers) X(glViewport) X(glClearColor) X(glClear) X(glFinish) X(glReadPixels) X(glCreateShader) X(glShaderSource) X(glCompileShader) X(glGetShaderiv) X(glGetShaderInfoLog) X(glCreateProgram) X(glAttachShader) X(glBindAttribLocation) X(glLinkProgram) X(glGetProgramiv) X(glGetProgramInfoLog) X(glUseProgram) X(glVertexAttribPointer) X(glEnableVertexAttribArray) X(glDrawArrays) X(glDeleteShader) X(glDeleteProgram)
#define DECL(name) static __typeof__(&name) p_##name;
EGL_FUNCTIONS(DECL)
GL_FUNCTIONS(DECL)
#undef DECL
static int fail(const char *stage) {
  printf("GPU_RENDER FAIL stage=%s EGL_error=%#x GL_error=%#x\n", stage,
         p_eglGetError ? p_eglGetError() : 0, p_glGetError ? p_glGetError() : 0);
  fflush(stdout);return 1;
}
static GLuint shader(GLenum type, const char *text) {
  GLuint id=p_glCreateShader(type);GLint ok=0;
  p_glShaderSource(id,1,&text,NULL);p_glCompileShader(id);p_glGetShaderiv(id,GL_COMPILE_STATUS,&ok);
  if (!ok) {char log[1024]={0};p_glGetShaderInfoLog(id,sizeof(log)-1,NULL,log);printf("GPU_RENDER shader_log=%s\n",log);return 0;}
  return id;
}
static int pixel(const char *stage, unsigned int red, unsigned int green, unsigned int blue) {
  unsigned char p[4]={0};p_glFinish();p_glReadPixels(8,8,1,1,GL_RGBA,GL_UNSIGNED_BYTE,p);
  printf("GPU_RENDER pixel stage=%s rgba=%u,%u,%u,%u\n",stage,p[0],p[1],p[2],p[3]);
  return p_glGetError()==GL_NO_ERROR && abs((int)p[0]-(int)red)<=2 && abs((int)p[1]-(int)green)<=2 && abs((int)p[2]-(int)blue)<=2 && p[3]>=253;
}
int main(int argc,char **argv) {
  (void)argv;struct utsname u;
  setvbuf(stdout,NULL,_IONBF,0);
  if (argc!=1 || getuid()!=65534 || geteuid()!=65534 || getgid()!=65534 || uname(&u) || strcmp(u.release,"7.1.0-shield-bringup")) return 64;
  printf("GPU_RENDER begin uid=%u device=/dev/dri/renderD128 backend=GBM-renderFD-GLES2-FBO\n",getuid());
  void *egl=dlopen("libEGL.so.1",RTLD_NOW|RTLD_LOCAL),*gl=dlopen("libGLESv2.so.2",RTLD_NOW|RTLD_LOCAL);
  if (!egl || !gl) {printf("GPU_RENDER loader=%s\n",dlerror());return 1;}
#define LOAD_EGL(name) p_##name=(__typeof__(p_##name))dlsym(egl,#name);if(!p_##name)return fail(#name);
  EGL_FUNCTIONS(LOAD_EGL)
#undef LOAD_EGL
#define LOAD_GL(name) p_##name=(__typeof__(p_##name))dlsym(gl,#name);if(!p_##name)return fail(#name);
  GL_FUNCTIONS(LOAD_GL)
#undef LOAD_GL
  const char *paths[]={"/dev/dri","/dev/dri/renderD128","/sys/dev/char/226:128/device","/sys/dev/char/226:128/device/drm","/sys/dev/char/226:128/device/uevent"};
  for(unsigned int i=0;i<sizeof(paths)/sizeof(paths[0]);i++){struct stat st;errno=0;int rc=stat(paths[i],&st);printf("GPU_RENDER path=%s stat=%d errno=%d mode=%o uid=%u\n",paths[i],rc,errno,rc?0:(unsigned)(st.st_mode&0777),rc?0:st.st_uid);}
  int fd=open("/dev/dri/renderD128",O_RDWR|O_CLOEXEC|O_NOFOLLOW);struct stat device_stat;
  if(fd<0 || fstat(fd,&device_stat) || !S_ISCHR(device_stat.st_mode) || major(device_stat.st_rdev)!=226 || minor(device_stat.st_rdev)!=128){printf("GPU_RENDER render_open_errno=%d\n",errno);return fail("verified-render-FD");}
  void *drm=dlopen("libdrm.so.2",RTLD_NOW|RTLD_LOCAL);
  if(drm){__typeof__(&drmGetDevice2) getdev=(__typeof__(&drmGetDevice2))dlsym(drm,"drmGetDevice2");__typeof__(&drmFreeDevice) freedev=(__typeof__(&drmFreeDevice))dlsym(drm,"drmFreeDevice");if(getdev&&freedev){drmDevicePtr info=NULL;int rc=getdev(fd,0,&info);printf("GPU_RENDER drmGetDevice2=%d bustype=%d\n",rc,rc? -1:info->bustype);if(!rc)freedev(&info);}}
  void *gbmlib=dlopen("libgbm.so.1",RTLD_NOW|RTLD_LOCAL);if(!gbmlib)return fail("load-gbm");
  __typeof__(&gbm_create_device) create_gbm=(__typeof__(&gbm_create_device))dlsym(gbmlib,"gbm_create_device");
  __typeof__(&gbm_device_destroy) destroy_gbm=(__typeof__(&gbm_device_destroy))dlsym(gbmlib,"gbm_device_destroy");
  if(!create_gbm || !destroy_gbm)return fail("gbm-functions");
  struct gbm_device *gbm=create_gbm(fd);if(!gbm)return fail("gbm-create-verified-render-FD");
  PFNEGLGETPLATFORMDISPLAYEXTPROC platform=(PFNEGLGETPLATFORMDISPLAYEXTPROC)p_eglGetProcAddress("eglGetPlatformDisplayEXT");
  if(!platform)return fail("GBM-platform-extension");
  EGLDisplay display=platform(EGL_PLATFORM_GBM_KHR,gbm,NULL);EGLint major=0,minor=0;
  if(display==EGL_NO_DISPLAY || !p_eglInitialize(display,&major,&minor))return fail("egl-initialize");
  printf("GPU_RENDER EGL=%d.%d vendor=%s\n",major,minor,p_eglQueryString(display,EGL_VENDOR));
  if(!p_eglBindAPI(EGL_OPENGL_ES_API))return fail("bind-GLES");
  const EGLint attrs[]={EGL_SURFACE_TYPE,0,EGL_RENDERABLE_TYPE,EGL_OPENGL_ES2_BIT,EGL_RED_SIZE,8,EGL_GREEN_SIZE,8,EGL_BLUE_SIZE,8,EGL_ALPHA_SIZE,8,EGL_NONE};
  EGLConfig config;EGLint configs=0;
  if(!p_eglChooseConfig(display,attrs,&config,1,&configs) || configs!=1)return fail("choose-config");
  const EGLint ctxattrs[]={EGL_CONTEXT_CLIENT_VERSION,2,EGL_NONE};
  EGLContext context=p_eglCreateContext(display,config,EGL_NO_CONTEXT,ctxattrs);if(context==EGL_NO_CONTEXT)return fail("create-context");
  EGLSurface surface=EGL_NO_SURFACE;
  if(!p_eglMakeCurrent(display,surface,surface,context))return fail("make-current");
  const char *renderer=(const char*)p_glGetString(GL_RENDERER),*version=(const char*)p_glGetString(GL_VERSION);
  printf("GPU_RENDER renderer=%s GL=%s\n",renderer?renderer:"NULL",version?version:"NULL");
  if(!renderer || strcasestr(renderer,"llvmpipe") || strcasestr(renderer,"softpipe") || strcasestr(renderer,"swrast") || strcasestr(renderer,"swiftshader") || (!strcasestr(renderer,"NV12B") && !strcasestr(renderer,"GM20B")))return fail("hardware-renderer-required");
  GLuint texture=0,framebuffer=0;p_glGenTextures(1,&texture);p_glBindTexture(GL_TEXTURE_2D,texture);p_glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);p_glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);p_glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA,16,16,0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);p_glGenFramebuffers(1,&framebuffer);p_glBindFramebuffer(GL_FRAMEBUFFER,framebuffer);p_glFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,texture,0);if(p_glCheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE)return fail("offscreen-FBO");
  p_glViewport(0,0,16,16);p_glClearColor(0.125f,0.25f,0.5f,1.0f);p_glClear(GL_COLOR_BUFFER_BIT);
  if(!pixel("clear",32,64,128))return fail("clear-readback");
  GLuint vs=shader(GL_VERTEX_SHADER,"attribute vec2 position; void main(){gl_Position=vec4(position,0.0,1.0);}"),fs=shader(GL_FRAGMENT_SHADER,"precision mediump float; void main(){gl_FragColor=vec4(0.75,0.25,0.125,1.0);}");
  if(!vs || !fs)return fail("compile-shaders");
  GLuint program=p_glCreateProgram();p_glAttachShader(program,vs);p_glAttachShader(program,fs);p_glBindAttribLocation(program,0,"position");p_glLinkProgram(program);GLint linked=0;p_glGetProgramiv(program,GL_LINK_STATUS,&linked);
  if(!linked){char log[1024]={0};p_glGetProgramInfoLog(program,sizeof(log)-1,NULL,log);printf("GPU_RENDER program_log=%s\n",log);return fail("link-program");}
  const GLfloat vertices[]={-1,-1,3,-1,-1,3};GLuint buffer=0;p_glGenBuffers(1,&buffer);p_glBindBuffer(GL_ARRAY_BUFFER,buffer);p_glBufferData(GL_ARRAY_BUFFER,sizeof(vertices),vertices,GL_STATIC_DRAW);p_glUseProgram(program);p_glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,NULL);p_glEnableVertexAttribArray(0);p_glDrawArrays(GL_TRIANGLES,0,3);
  if(!pixel("triangle",191,64,32))return fail("triangle-readback");
  p_glDeleteBuffers(1,&buffer);p_glDeleteFramebuffers(1,&framebuffer);p_glDeleteTextures(1,&texture);p_glDeleteProgram(program);p_glDeleteShader(vs);p_glDeleteShader(fs);p_eglMakeCurrent(display,EGL_NO_SURFACE,EGL_NO_SURFACE,EGL_NO_CONTEXT);p_eglDestroyContext(display,context);p_eglTerminate(display);destroy_gbm(gbm);close(fd);
  printf("GPU_RENDER PASS hardware=GM20B api=GLES2 clear_and_shader_triangle_pixel_readbacks=2 USB_filesystem_writes=0\n");return 0;
}
