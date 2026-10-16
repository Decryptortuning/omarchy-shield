#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
typedef uint64_t u64;
#define CONFIG_IOMMU_API 1
#define CONFIG_ARM_DMA_USE_IOMMU 0
#define IS_ENABLED(x) (x)
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define PAGE_MASK (~(PAGE_SIZE-1))
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095L)
#define PTR_ERR(p) ((int)(intptr_t)(p))
#define dev_err(...) ((void)0)
#define dev_warn(...) ((void)0)
#define dev_info(...) ((void)0)
struct device { int unused; };
struct platform_device { struct device dev; };
struct iommu_domain { struct {u64 aperture_start,aperture_end;bool force_aperture;} geometry; unsigned long pgsize_bitmap; };
struct nvkm_device_tegra {struct platform_device *pdev; const struct { unsigned int iommu_bit; } *func; struct {int mutex,mm;unsigned int pgshift;struct iommu_domain *domain;} iommu;};
static struct iommu_domain domain;
static bool mapped;
static int fail_alloc,fail_attach,fail_mm,freed,detached,attached,initialized;
static u64 mm_length;
static void mutex_init(int *m) {*m=1;}
static bool device_iommu_mapped(struct device *d) {return mapped;}
static struct iommu_domain *iommu_paging_domain_alloc(struct device *d) {return fail_alloc?(void*)(intptr_t)fail_alloc:&domain;}
static unsigned int fls(unsigned long x) {return x?8*sizeof(unsigned int)-__builtin_clz((unsigned int)x):0;}
static int iommu_attach_device(struct iommu_domain *d,struct device *dev) {assert(d==&domain);attached++;return fail_attach;}
static int nvkm_mm_init(int *mm,int a,int b,u64 length,int c) {assert(a==0 && b==0 && c==1);mm_length=length;initialized++;return fail_mm;}
static void iommu_detach_device(struct iommu_domain *d,struct device *dev) {assert(d==&domain);detached++;}
static void iommu_domain_free(struct iommu_domain *d) {assert(d==&domain);freed++;}
/* DRIVER */
static void fixture(struct nvkm_device_tegra *t) {
  memset(&domain,0,sizeof(domain));domain.geometry.aperture_end=0xffffffff;domain.geometry.force_aperture=true;domain.pgsize_bitmap=4096;
  memset(&t->iommu,0,sizeof(t->iommu));mapped=true;fail_alloc=fail_attach=fail_mm=freed=detached=attached=initialized=0;mm_length=0;
}
int main(void) {
  struct platform_device p;typeof(*((struct nvkm_device_tegra*)0)->func) f={34};struct nvkm_device_tegra t={.pdev=&p,.func=&f};
  fixture(&t);assert(nvkm_device_tegra_probe_iommu(&t)==0);assert(t.iommu.domain==&domain && t.iommu.pgshift==12 && mm_length==0x100000 && attached==1 && initialized==1 && freed==0);
  fixture(&t);fail_alloc=-ENOMEM;assert(nvkm_device_tegra_probe_iommu(&t)==-ENOMEM);assert(!t.iommu.domain && !t.iommu.pgshift && !attached && !freed);
  fixture(&t);domain.pgsize_bitmap=0;assert(nvkm_device_tegra_probe_iommu(&t)==-EINVAL);assert(freed==1 && !attached && !t.iommu.domain);
  fixture(&t);domain.pgsize_bitmap=2048;assert(nvkm_device_tegra_probe_iommu(&t)==0 && t.iommu.pgshift==11 && mm_length==0x200000);
  fixture(&t);domain.geometry.aperture_start=4096;assert(nvkm_device_tegra_probe_iommu(&t)==-EINVAL);assert(freed==1 && !attached && !initialized);
  fixture(&t);domain.geometry.aperture_end=2047;assert(nvkm_device_tegra_probe_iommu(&t)==-EINVAL);assert(freed==1 && !attached && !initialized);
  fixture(&t);fail_attach=-EIO;assert(nvkm_device_tegra_probe_iommu(&t)==-EIO);assert(freed==1 && attached==1 && !initialized && !detached && !t.iommu.domain);
  fixture(&t);fail_mm=-ENOMEM;assert(nvkm_device_tegra_probe_iommu(&t)==-ENOMEM);assert(freed==1 && attached==1 && initialized==1 && detached==1 && !t.iommu.domain && !t.iommu.pgshift);
  fixture(&t);mapped=false;assert(nvkm_device_tegra_probe_iommu(&t)==0 && !attached && !initialized && !t.iommu.domain);
  puts("PASS: actual Nouveau IOMMU setup: paging allocation, page/aperture refusal, attach/MM failures, cleanup and returned errors");return 0;
}
