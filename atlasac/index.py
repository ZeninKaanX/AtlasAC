"""Persistent local filename index and inspection cache. One writer, WAL readers."""
import json
from pathlib import Path
import sqlite3
import time

class FileIndex:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.db=sqlite3.connect(self.path,timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,size INTEGER,modified_ns INTEGER,kind TEXT,sha256 TEXT,scan_id TEXT,token TEXT,cache TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS files_scan ON files(scan_id)')
        self.pending=0
    def cached(self,path,token):
        row=self.db.execute('SELECT cache FROM files WHERE path=? AND token=?',(str(path),token)).fetchone()
        try:return json.loads(row[0]) if row and row[0] else None
        except (ValueError,TypeError):return None
    def put(self,path,st,scan_id,token,result):
        record=result.get('file') or {}
        cache=json.dumps(result,ensure_ascii=False) if result.get('fingerprint') and not result['issues'] else None
        self.db.execute('INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?,?)',(str(path),st.st_size,st.st_mtime_ns,record.get('format',''),record.get('sha256'),scan_id,token,cache))
        self.pending+=1
        if self.pending>=500:self.db.commit();self.pending=0
    def flush(self):
        self.db.commit();self.pending=0
    def close(self):
        self.db.commit();self.db.close()


def search_files(path,scan_id,term='',limit=500):
    uri=Path(path).resolve().as_uri()+'?mode=ro'
    db=sqlite3.connect(uri,uri=True,timeout=1)
    deadline=time.monotonic()+1
    db.set_progress_handler(lambda:time.monotonic()>deadline,10000)
    try:
        escaped=term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        rows=db.execute("SELECT path,size,kind,sha256 FROM files WHERE scan_id=? AND path LIKE ? ESCAPE '\\' LIMIT ?",(scan_id,'%'+escaped+'%',limit)).fetchall()
        return [dict(zip(('path','size','format','sha256'),row)) for row in rows]
    finally:db.close()
