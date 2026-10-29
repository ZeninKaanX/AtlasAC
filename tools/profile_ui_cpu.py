"""Measure native UI rendering CPU independently of the file scanner.
CPU percentage is process CPU seconds / wall seconds * 100 (one logical core=100%).
The scan strip and verdict use display fixtures, not fabricated scan measurements.
"""
import argparse,json,os,sys,time
from pathlib import Path
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1]);p.add_argument('--seconds',type=float,default=4);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
sys.path.insert(0,str(args.source))
from PySide6.QtWidgets import QApplication
from PySide6.QtTest import QTest
from atlasac.desktop import AtlasWindow
app=QApplication([]);window=AtlasWindow();window.resize(1280,860);window.show();window.reveal.sound.setMuted(True);results=[]
try:
 for mode in ('idle','fish','reveal','minimized'):
  window.reveal.finish();window.progress_bar.hide();window.showNormal()
  if mode=='fish':window.progress_bar.show()
  if mode=='reveal':window.reveal.start({'status':'completed','findings':[]})
  if mode=='minimized':window.showMinimized()
  QTest.qWait(1200);start=time.monotonic();cpu=time.process_time()
  while time.monotonic()-start<args.seconds:QTest.qWait(10)
  wall=time.monotonic()-start;used=time.process_time()-cpu
  results.append({'mode':mode,'wall_seconds':round(wall,3),'cpu_seconds':round(used,4),'one_core_cpu_percent':round(used/wall*100,2)})
 report={'scope':'Qt native UI only; no scanning; 1280x860; offscreen; one-core CPU percentages, not Task Manager total-machine percentages','logical_cpus':os.cpu_count(),'samples':results}
 args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
finally:window.close();app.processEvents()
