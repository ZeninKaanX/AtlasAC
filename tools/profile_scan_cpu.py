"""Measure real scanner process CPU on an explicitly provided folder, without GUI.
Run baseline/current source against identical files and independent cold indexes.
This is process CPU; collector subprocess CPU is not included (artifacts disabled).
"""
import argparse,hashlib,json,sys,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('folder',type=Path);p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
sys.path.insert(0,str(args.source))
from atlasac.engine import load_rules
from atlasac.paths import RULES
from atlasac.systemscan import system_scan
def digest(path):
 with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
manifest=[{'file':p.name,'size':p.stat().st_size,'sha256':digest(p)} for p in sorted(args.folder.iterdir()) if p.is_file()]
with tempfile.TemporaryDirectory() as cache:
 start=time.monotonic();cpu=time.process_time();report=system_scan(load_rules(RULES),[args.folder],data_dir=cache,artifacts=False);used=time.process_time()-cpu;wall=time.monotonic()-start
 result={'scope':'Scanner process only; real files; cold independent index; no GUI or collectors; one-core CPU=100%', 'manifest':manifest,'wall_seconds':round(wall,4),'cpu_seconds':round(used,4),'one_core_cpu_percent':round(100*used/wall,2),'scan':{k:report.get(k) for k in ('version','status','indexed_files','content_files','archive_reuses','issues_total','cpu_target_cores')},'matches':[{'file':Path(f['path']).name,'rule':f['rule']} for f in report['findings']]}
 args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
