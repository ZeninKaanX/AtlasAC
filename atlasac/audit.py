"""Minimal local operational events, with no paths, command contents or identifiers."""
import json,time
from pathlib import Path
from .privacy import RETENTION_DAYS
from .securestore import private_directory,private_permissions,check_plain,write_json


class AuditTrail:
    def __init__(self,base=None):
        self.base=private_directory(base or Path.home()/'.atlasac');self.path=check_plain(self.base/'audit.json')
        self.rows=[]
        if self.path.exists():
            private_permissions(self.path)
            if self.path.stat().st_size<=1024*1024:
                try:self.rows=json.loads(self.path.read_text(encoding='utf-8'))
                except (ValueError,UnicodeError):pass
        if not isinstance(self.rows,list):self.rows=[]
        cutoff=time.time()-RETENTION_DAYS*86400
        self.rows=[{'time':r['time'],'event':r['event'],'count':r.get('count',0)} for r in self.rows if isinstance(r,dict) and isinstance(r.get('time'),(int,float)) and r['time']>=cutoff and r.get('event') in ('scan-start','scan-complete','scan-partial','scan-cancelled','report-export')][-2000:]
        if self.path.exists():write_json(self.path,self.rows)

    def record(self,event,count=0):
        if event not in ('scan-start','scan-complete','scan-partial','scan-cancelled','report-export'):raise ValueError('Bilinmeyen işlem olayı')
        cutoff=time.time()-RETENTION_DAYS*86400
        self.rows=[r for r in self.rows if r['time']>=cutoff]
        self.rows.append({'time':time.time(),'event':event,'count':int(count)})
        self.rows=self.rows[-2000:];write_json(self.path,self.rows)

    def purge(self):
        self.rows=[]
        if self.path.exists():check_plain(self.path);self.path.unlink();return 1
        return 0
