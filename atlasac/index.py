"""Persistent local filename index and inspection cache. One writer, WAL readers."""
from pathlib import Path
import sqlite3
import time
from .privacy import RETENTION_DAYS
from .securestore import private_directory,private_permissions,check_plain

class FileIndex:
    def __init__(self,path):
        self.path=check_plain(path);private_directory(self.path.parent)
        for name in ('','-wal','-shm'):
            side=check_plain(str(self.path)+name)
            if side.exists():private_permissions(side)
        self.db=sqlite3.connect(self.path,timeout=10)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.execute('PRAGMA secure_delete=ON')
        private_permissions(self.path)
        self.db.execute('CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,size INTEGER,modified_ns INTEGER,kind TEXT,sha256 TEXT,scan_id TEXT,token TEXT,cache TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS files_scan ON files(scan_id)')
        columns={r[1] for r in self.db.execute('PRAGMA table_info(files)')}
        if 'seen_at' not in columns:self.db.execute('ALTER TABLE files ADD COLUMN seen_at REAL NOT NULL DEFAULT 0')
        self.db.execute('UPDATE files SET cache=NULL WHERE cache IS NOT NULL')
        self.db.execute('DELETE FROM files WHERE seen_at < ?',(time.time()-RETENTION_DAYS*86400,))
        self.db.commit();self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        self._protect_sidecars()
        self.pending=0
    def cached(self,path,token):
        # Player-writable persistent data is never an authority for inspection results.
        return None
    def put(self,path,st,scan_id,token,result):
        record=result.get('file') or {}
        cache=None  # Index metadata only; never persist trusted findings or clean verdicts.
        self.db.execute('INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?,?,?)',(str(path),st.st_size,st.st_mtime_ns,record.get('format',''),record.get('sha256'),scan_id,token,cache,time.time()))
        self.pending+=1
        if self.pending>=500:self.db.commit();self.pending=0
    def _protect_sidecars(self):
        for suffix in ('-wal','-shm'):
            path=check_plain(str(self.path)+suffix)
            if path.exists():private_permissions(path)
    def flush(self):
        self.db.commit();self.pending=0
    def close(self):
        self.db.commit();self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)');self.db.close()


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


def purge_index(base):
    removed=0
    for suffix in ('','-wal','-shm'):
        path=check_plain(Path(base)/('file-index.sqlite3'+suffix))
        if path.exists():path.unlink();removed+=1
    return removed


def maintain_index(base):
    path=check_plain(Path(base)/'file-index.sqlite3')
    if path.exists():
        index=FileIndex(path);index.close()
