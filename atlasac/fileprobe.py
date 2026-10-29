"""Bounded per-file inspection and reliable content-change fingerprints."""
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import zipfile
from .findingicons import embedded_icon
from .engine import inspect_archive, match_file_signatures, MAX_FILE, MAX_ARCHIVE_SECONDS


@lru_cache(maxsize=1)
def windows_fingerprint_api():
    import ctypes as c
    import msvcrt
    class Basic(c.Structure):
        _fields_ = [('created',c.c_longlong),('accessed',c.c_longlong),('written',c.c_longlong),('changed',c.c_longlong),('attributes',c.c_ulong)]
    k=c.WinDLL('kernel32',use_last_error=True)
    fn=k.GetFileInformationByHandleEx;fn.argtypes=[c.c_void_p,c.c_int,c.c_void_p,c.c_ulong];fn.restype=c.c_int
    return c,msvcrt,Basic,fn


def fingerprint(st, handle=None):
    change = st.st_ctime_ns
    if os.name == 'nt':
        c,msvcrt,Basic,fn=windows_fingerprint_api()
        info=Basic()
        if handle is None or not fn(msvcrt.get_osfhandle(handle),0,c.byref(info),c.sizeof(info)):
            return None  # Never trust creation time as a Windows content-change counter.
        change=info.changed
    return [st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,change]


def probe(path, rules, cancel, cached=None, content_cache=None):
    result={'path':str(path),'file':None,'findings':[],'issues':[],'bytes_read':0,'cache_hit':False,'fingerprint':None,'archive_reused':False}
    try:
        if cancel.is_set():raise InterruptedError('Tarama durduruldu')
        with os.fdopen(os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0)),'rb') as f:
            before=os.fstat(f.fileno())
            if not stat.S_ISREG(before.st_mode):return result
            stamp=fingerprint(before,f.fileno());result['fingerprint']=stamp
            if stamp and cached and cached.get('fingerprint')==stamp:
                result.update(cached);result['cache_hit']=True;result['bytes_read']=0;result['archive_reused']=False
                return result
            head=f.read(4);result['bytes_read']+=len(head)
            kind='ZIP' if head in (b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08') else 'PE' if head[:2]==b'MZ' else 'ELF' if head==b'\x7fELF' else ''
            archive=kind=='ZIP' or Path(path).suffix.lower() in ('.jar','.zip')
            if not archive:
                # Python's ZIP detector also handles overlays and ZIP comments.
                archive=zipfile.is_zipfile(f)
                result['bytes_read']+=min(before.st_size,65579)
            if not kind and archive:kind='ZIP-overlay'
            if not kind and Path(path).suffix.lower() not in ('.exe','.dll','.so','.pyd'):
                if stamp!=fingerprint(os.fstat(f.fileno()),f.fileno()):
                    result['fingerprint']=None
                    raise ValueError('Dosya tarama sırasında değişti')
                return result
            record={'path':str(path),'size':before.st_size,'modified_ns':before.st_mtime_ns,'format':kind or 'binary','sha256':None}
            result['file']=record
            signature_size = any(s['size'] == before.st_size for rule in rules['rules'] for s in rule.get('file_signatures', []))
            if archive or rules['hashes'] or signature_size:
                if before.st_size>MAX_FILE:raise ValueError('İçerik inceleme boyutu sınırı (256 MiB)')
                f.seek(0);digest=hashlib.sha256()
                while block:=f.read(1024*1024):
                    if cancel.is_set():raise InterruptedError('Tarama durduruldu')
                    digest.update(block);result['bytes_read']+=len(block)
                sha=digest.hexdigest();record['sha256']=sha
                result['findings'].extend(match_file_signatures(rules, sha, before.st_size, str(path)))
                if sha in rules['hashes']:
                    result['findings'].append({'rule':'sha256','name':rules['hashes'][sha],'category':'custom','method':'sha256','path':str(path),'evidence':[sha],'note':'Yerel hash kuralıyla eşleşme; aktif kullanım kanıtı değildir.'})
            if archive:
                def inspect_content():
                    f.seek(0);content={'path':str(path),'findings':[],'issues':[]}
                    inspect_archive(f,str(path),rules,content['findings'],content['issues'],budget={'members':0,'bytes':0,'deadline':time.monotonic()+MAX_ARCHIVE_SECONDS,'cancel':cancel})
                    for finding in content['findings']:
                        rule=next((r for r in rules['rules'] if r['id']==finding['rule']),{})
                        if rule.get('embedded_icon') is False:continue
                        icon=embedded_icon(f,finding['path'])
                        if icon:finding['icon_png_base64']=icon
                    if stamp and stamp!=fingerprint(os.fstat(f.fileno()),f.fileno()):
                        raise ValueError('Dosya tarama sırasında değişti')
                    return content
                if content_cache and stamp:
                    content,reused=content_cache.inspect(record['sha256'],inspect_content,path);result['archive_reused']=reused
                else:content=inspect_content()
                result['findings'].extend(content['findings']);result['issues'].extend(content['issues'])
            after=fingerprint(os.fstat(f.fileno()),f.fileno())
            if stamp!=after:
                result['fingerprint']=None
                raise ValueError('Dosya tarama sırasında değişti')
    except (OSError,ValueError) as exc:
        result['issues'].append({'path':str(path),'reason':str(exc)[:220]});result['fingerprint']=None
    return result
