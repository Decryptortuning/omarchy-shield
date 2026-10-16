#!/usr/bin/env python3
"""Actual candidate functions, banked fake MMIO, allocator and error propagation."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess,tempfile

def function(s,name):
  m=re.search(r'^static[^;{]*\b'+re.escape(name)+r'\([^;]*?\n\{',s,re.M)
  if not m: raise ValueError(name)
  end=m.end();depth=1
  while depth:
    depth+=(s[end]=='{')-(s[end]=='}');end+=1
  return s[m.start():end]+'\n'

def main():
  p=argparse.ArgumentParser();p.add_argument('--kernel-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
  w=Path(__file__).resolve().parent.parent/'tests'
  paths=['drivers/iommu/tegra-smmu.c','drivers/gpu/drm/nouveau/nvkm/engine/device/tegra.c','drivers/memory/tegra/tegra210.c','include/dt-bindings/memory/tegra210-mc.h','drivers/memory/tegra/mc.c','drivers/of/platform.c']
  files={n:(a.kernel_source/n).read_text() for n in paths};s,n,soc,header,parent,of=(files[n] for n in paths)
  table=re.search(r'static const struct tegra_smmu_swgroup tegra210_swgroups\[\] = \{(.*?)\n\};',soc,re.S)[1]
  ids={n:int(v) for n,v in re.findall(r'^#define\s+(TEGRA_SWGROUP_\w+)\s+(\d+)\s*$',header,re.M)}
  groups=[(ids[g],int(r,16)) for g,r in re.findall(r'\.swgroup = (TEGRA_SWGROUP_\w+),\s+\.reg = (0x[0-9a-f]+)',table)]
  assert len(groups)==len(set(r for g,r in groups))==39 and (ids['TEGRA_SWGROUP_GPU'],0xaac) in groups
  for param in ['reset_inherited','preserve_disabled_gpu','quarantine_gpub_inherited']:
    assert f'static bool {param};' in s and f'module_param_named({param}, {param}, bool, 0400);' in s
  probe=s.split('struct tegra_smmu *tegra_smmu_probe(',1)[1].split('\nvoid tegra_smmu_remove',1)[0]
  order=['tegra_smmu_reset_handoff(smmu);','SMMU_PTC_CONFIG_ENABLE','smmu_flush_ptc_all(smmu);','smmu_flush_tlb(smmu);','smmu_writel(smmu, SMMU_CONFIG_ENABLE, SMMU_CONFIG);','smmu_flush(smmu);','err = iommu_device_register(','handoff_reset_complete = true;','return smmu;']
  offsets=[probe.index(x) for x in order];assert offsets==sorted(offsets)
  assert 'arch_initcall(tegra_mc_init);' in parent and 'arch_initcall_sync(of_platform_default_populate_init);' in of
  identity=function(s,'tegra_smmu_identity_attach');assert identity.index('tegra_smmu_disable(')<identity.index('tegra_smmu_as_unprepare(')
  prepare=function(s,'tegra_smmu_as_prepare');assert prepare.index('err = tegra_smmu_alloc_asid(')<prepare.index('if (err < 0)')<prepare.index('SMMU_PTB_ASID')
  names=['smmu_flush','tegra_smmu_alloc_asid','tegra_smmu_free_asid','tegra_smmu_find_swgroup','tegra_smmu_enable','tegra_smmu_disable','tegra_smmu_reset_handoff','tegra_smmu_check_handoff_reset']
  code=(w/'smmu-harness.c').read_text().replace('/* GROUPS */',',\n'.join(f'{{.swgroup={g},.reg=0x{r:x}}}' for g,r in groups)).replace('GPU_GROUP_ID',str(ids['TEGRA_SWGROUP_GPU'])).replace('/* DRIVER */','\n'.join(function(s,name) for name in names))
  helper=function(n,'nvkm_device_tegra_iommu_limit')
  gpu='''#include <assert.h>\n#include <stdbool.h>\n#include <stdint.h>\n#include <stdio.h>\ntypedef uint64_t u64;\nstruct iommu_domain { struct { u64 aperture_start,aperture_end; bool force_aperture; } geometry; };\n'''+helper+'''int main(void) { struct iommu_domain d={.geometry={0,0xffffffff,true}};
assert(nvkm_device_tegra_iommu_limit(&d,34)==0x100000000ULL);
d.geometry.force_aperture=false;assert(nvkm_device_tegra_iommu_limit(&d,34)==0x400000000ULL);
d.geometry.force_aperture=true;d.geometry.aperture_end=UINT64_MAX;assert(nvkm_device_tegra_iommu_limit(&d,34)==0x400000000ULL);
assert(nvkm_device_tegra_iommu_limit(&d,0)==0 && nvkm_device_tegra_iommu_limit(&d,64)==0);
d.geometry.aperture_start=4096;assert(nvkm_device_tegra_iommu_limit(&d,34)==0);
d.geometry.aperture_start=0;d.geometry.aperture_end=2047;assert(nvkm_device_tegra_iommu_limit(&d,34)==2048);
d.geometry.aperture_end=4095;assert(nvkm_device_tegra_iommu_limit(&d,34)==4096);
d.geometry.aperture_end=0;assert(nvkm_device_tegra_iommu_limit(&d,34)==1);
d.geometry.aperture_end=UINT64_MAX;assert(nvkm_device_tegra_iommu_limit(&d,63)==(1ULL<<63));
puts("PASS: actual Nouveau allocator aperture helper: 4GiB forced vs16GiB tag, bounds, invalid bit/start, overflow"); return 0; }'''
  gpuprobe=function(n,'nvkm_device_tegra_probe_iommu')
  assert 'ret = PTR_ERR(tdev->iommu.domain);' in gpuprobe and 'return ret;' in gpuprobe
  assert gpuprobe.count('ret = -EINVAL;')==2
  assert 'limit >> tdev->iommu.pgshift, 1' in gpuprobe
  ctor=n.split('int\nnvkm_device_tegra_new(',1)[1].split('#else',1)[0]
  assert ctor.index('ret = nvkm_device_tegra_probe_iommu(tdev);\n\tif (ret)\n\t\tgoto free;') < ctor.index('ret = nvkm_device_tegra_power_up(tdev);')
  gpu_probe=(w/'nouveau-iommu-harness.c').read_text().replace('/* DRIVER */',helper+'\n'+gpuprobe)
  outputs=[]
  with tempfile.TemporaryDirectory(prefix='shield-quarantine-check-') as tmp:
    tmp=Path(tmp)
    for name,text in [('smmu',code),('nouveau',gpu),('nouveau-probe',gpu_probe)]:
      (tmp/f'{name}.c').write_text(text)
      subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-fsanitize=undefined','-o',str(tmp/name),str(tmp/f'{name}.c')],check=True)
      r=subprocess.run([str(tmp/name)],capture_output=True,text=True,check=True);outputs.append(r.stdout.strip());print(outputs[-1])
  report={'source_sha256':{n:hashlib.sha256(t.encode()).hexdigest() for n,t in files.items()},'actual_functions':names+['nvkm_device_tegra_iommu_limit'],'results':outputs,'actual_probe_allocator_detach_failure_order_reviewed':True,'scope':'Actual functions compiled with banked fake MMIO; structural consumer order; no physical hardware claim','GPU_hardware_qualified':False}
  a.output.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
