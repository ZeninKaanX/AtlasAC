"""Concurrent discovery with a bounded RAM buffer and a private temporary spool.

The spool holds work paths/metadata, never trusted findings or clean verdicts.
Every queued candidate is still opened and inspected from disk by fileprobe.
"""
import hmac,json,os,secrets,struct,tempfile,threading,time
from collections import deque
from pathlib import Path
from .filepolicy import candidate_name,directory_priority
from .assessment import name_context


class ScanPlan:
    def __init__(self,roots,skipped,excluded,cancel,base):
        self.roots=roots;self.skipped=skipped;self.excluded=set(excluded);self.cancel=cancel
        self.excluded_names={os.path.normcase(str(p)) for p in excluded}
        self.stream=tempfile.TemporaryFile(dir=base,buffering=0)
        self.lock=threading.Condition();self.stop=threading.Event()
        self.write_offset=0;self.read_offset=0;self.buffer=b'';self.buffer_offset=0
        self.priority=deque();self.key=secrets.token_bytes(32);self.write_sequence=0;self.read_sequence=0
        self.seen=0;self.candidates=0;self.ignored=0;self.directories=0
        self.done=False;self.complete=False;self.error=None;self.closing=False
        self.thread=threading.Thread(target=self._discover,name='AtlasAC-discovery',daemon=True)
        self.thread.start()

    def snapshot(self):
        with self.lock:
            return {'files_seen':self.seen,'discovered_candidates':self.candidates,
                    'ignored_files':self.ignored,'directories_seen':self.directories,
                    'discovery_complete':self.complete,'discovery_finished':self.done,
                    'discovery_error':self.error}

    def take(self,count):
        rows=[]
        with self.lock:
            while len(rows)<count:
                if self.priority:rows.append(self.priority.popleft());continue
                available=len(self.buffer)-self.buffer_offset
                length=struct.unpack_from('>I',self.buffer,self.buffer_offset)[0] if available>=4 else None
                if length is not None and length>1024*1024:raise ValueError('Dosya listesi kaydı boyut sınırını aştı')
                if length is not None and available>=length+4:
                    start=self.buffer_offset+4;record=self.buffer[start:start+length];self.buffer_offset=start+length
                    if len(record)<41:raise ValueError('Geçici dosya listesi kaydı eksik')
                    signed,tag=record[:-32],record[-32:]
                    sequence=struct.unpack_from('>Q',signed)[0]
                    if sequence!=self.read_sequence or not hmac.compare_digest(tag,hmac.digest(self.key,signed,'sha256')):
                        raise ValueError('Geçici dosya listesi bütünlüğü doğrulanamadı')
                    self.read_sequence+=1;payload=signed[8:]
                    if payload[:1]==b'F':
                        size,modified,path=payload[1:].split(b'\0',2)
                        rows.append({'kind':'file','path':os.fsdecode(path),'size':int(size),'modified_ns':int(modified)})
                    else:rows.append(json.loads(payload[1:]))
                    continue
                if self.read_offset>=self.write_offset:
                    if self.done and available:
                        self.error='Dosya listesi eksik kaydedildi';self.complete=False;self.buffer=b'';self.buffer_offset=0
                    break
                self.stream.seek(self.read_offset)
                chunk=self.stream.read(min(65536,self.write_offset-self.read_offset))
                if not chunk:raise OSError('Dosya listesi okunamadı')
                self.read_offset+=len(chunk);self.buffer=self.buffer[self.buffer_offset:]+chunk;self.buffer_offset=0
        return rows

    def exhausted(self):
        with self.lock:return self.done and not self.priority and self.read_offset==self.write_offset and self.buffer_offset==len(self.buffer)

    def wait(self):
        with self.lock:
            if not self.done and not self.priority and self.read_offset==self.write_offset:self.lock.wait(.05)

    def close(self):
        self.stop.set()
        with self.lock:self.closing=True;self.lock.notify_all()
        self.thread.join(timeout=.2)
        if not self.thread.is_alive():self.stream.close()

    def _discover(self):
        rows=[];seen=candidates=ignored=directories=0;last_publish=time.monotonic()
        def publish():
            nonlocal last_publish
            chunks=[]
            with self.lock:
                for row in rows:
                    if row['kind']=='file':
                        if row['path'].lower().endswith(('.jar','.zip')) and len(self.priority)<1024:
                            self.priority.append(row);continue
                        payload=b'F'+str(row['size']).encode()+b'\0'+str(row['modified_ns']).encode()+b'\0'+os.fsencode(row['path'])
                    else:payload=b'J'+json.dumps(row,ensure_ascii=True).encode()
                    signed=struct.pack('>Q',self.write_sequence)+payload;self.write_sequence+=1
                    record=signed+hmac.digest(self.key,signed,'sha256')
                    chunks.append(struct.pack('>I',len(record))+record)
                data=b''.join(chunks)
                if data:
                    self.stream.seek(self.write_offset)
                    view=memoryview(data)
                    while view:
                        written=self.stream.write(view)
                        if not written:raise OSError('Dosya listesi yazılamadı')
                        view=view[written:];self.write_offset+=written
                self.seen=seen;self.candidates=candidates;self.ignored=ignored;self.directories=directories
                self.lock.notify_all()
            rows.clear();last_publish=time.monotonic()
        def issue(path,reason):rows.append({'kind':'issue','path':str(path),'reason':str(reason)[:220]})
        stack=[(p,any(p==folder or p.is_relative_to(folder) for folder in self.skipped)) for p in reversed(self.roots)]
        try:
            while stack and not self.stop.is_set() and not self.cancel.is_set():
                directory,archives_only=stack.pop();children=[];directories+=1
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if self.stop.is_set() or self.cancel.is_set():break
                            if os.path.normcase(entry.path) in self.excluded_names:continue
                            try:
                                if entry.is_symlink():issue(entry.path,'Bağlantı / yeniden yönlendirme izlenmedi');continue
                                if entry.is_dir(follow_symlinks=False):
                                    path=Path(entry.path)
                                    if path in self.excluded:continue
                                    if os.name=='nt' and getattr(entry.stat(follow_symlinks=False),'st_file_attributes',0)&0x400:
                                        issue(path,'Bağlantı / yeniden yönlendirme izlenmedi');continue
                                    context=name_context(path)
                                    if context:rows.append({'kind':'context','row':context})
                                    children.append((path,archives_only or path in self.skipped))
                                elif entry.is_file(follow_symlinks=False):
                                    seen+=1
                                    # No Path allocation, exclusion search or stat for ignored media.
                                    if not candidate_name(entry.name,archives_only):ignored+=1
                                    else:
                                        st=entry.stat(follow_symlinks=False)
                                        if getattr(st,'st_file_attributes',0)&0x400:issue(entry.path,'Bağlantı / yeniden yönlendirme izlenmedi')
                                        else:
                                            candidates+=1
                                            rows.append({'kind':'file','path':entry.path,'size':st.st_size,'modified_ns':st.st_mtime_ns})
                            except OSError as exc:issue(entry.path,exc)
                            if len(rows)>=128 or time.monotonic()-last_publish>=.1:publish()
                except OSError as exc:issue(directory,exc)
                stack.extend(sorted(children,key=lambda pair:directory_priority(*pair),reverse=True))
            publish()
            self.complete=not stack and not self.stop.is_set() and not self.cancel.is_set()
        except Exception as exc:self.error=str(exc)[:220]
        finally:
            with self.lock:
                self.done=True;self.lock.notify_all()
                if self.closing:self.stream.close()
