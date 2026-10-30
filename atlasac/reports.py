"""Private, minimised reports with bounded count and age retention."""
import json,time,uuid
from pathlib import Path
from .privacy import minimize_report,RETENTION_DAYS,REPORT_LIMIT
from .securestore import private_directory,private_permissions,write_json,check_plain


class ReportHistory:
    def __init__(self,directory=None):
        self.directory=Path(directory) if directory else Path.home()/'.atlasac'/'reports'
        if directory is None:private_directory(self.directory.parent)
        private_directory(self.directory)
        self.maintain()

    def maintain(self):
        cutoff=time.time()-RETENTION_DAYS*86400
        for i,path in enumerate(self.paths()):
            check_plain(path)
            if i>=REPORT_LIMIT or path.stat().st_mtime<cutoff:path.unlink();continue
            private_permissions(path)
            if path.stat().st_size>16*1024*1024:continue
            try:
                original=json.loads(path.read_text(encoding='utf-8'));clean=minimize_report(original)
                if clean!=original:
                    stamp=path.stat().st_mtime_ns;write_json(path,clean)
                    import os
                    os.utime(path,ns=(stamp,stamp))
            except (ValueError,UnicodeError):continue

    def save(self,report):
        private_directory(self.directory)
        name=report['started_at'].replace(':','-').replace('/','-')+'-'+uuid.uuid4().hex[:8]
        target=self.directory/(name+'.json');write_json(target,minimize_report(report));self.maintain()
        return target

    def paths(self):
        return sorted(self.directory.glob('*.json'),reverse=True) if self.directory.exists() else []

    def purge(self):
        removed=0
        for path in self.paths():check_plain(path);path.unlink();removed+=1
        return removed

    def read(self,path):
        path=check_plain(path)
        if path.parent.resolve()!=self.directory.resolve() or path.stat().st_size>16*1024*1024:raise ValueError('Geçersiz rapor yolu veya boyutu')
        report=json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(report,dict) or not all(k in report for k in ('started_at','status','roots','findings','files','issues')):raise ValueError('Geçersiz rapor')
        return minimize_report(report)
