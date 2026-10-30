"""Bounded per-scan reuse after SHA-256 verification, including concurrent copies."""
from collections import OrderedDict
from concurrent.futures import Future
from threading import Lock
import copy,json

class ContentCache:
    def __init__(self,max_bytes=16*1024*1024,signature_sizes=None):
        self.lock=Lock();self.items=OrderedDict();self.bytes=0;self.max_bytes=max_bytes
        self.signature_sizes=signature_sizes
    def inspect(self,digest,reader,path):
        with self.lock:
            entry=self.items.get(digest);owner=entry is None
            if owner:
                future=Future();self.items[digest]=(future,0)
            else:future,size=entry;self.items.move_to_end(digest)
        if owner:
            try:
                result=reader();future.set_result(result)
                size=len(json.dumps(result,ensure_ascii=False).encode())
                with self.lock:
                    if result['issues'] or size>self.max_bytes:self.items.pop(digest,None)
                    else:
                        self.items[digest]=(future,size);self.bytes+=size
                        for key,(other,cost) in list(self.items.items()):
                            if self.bytes<=self.max_bytes:break
                            if other.done():self.items.pop(key);self.bytes-=cost
            except BaseException as exc:
                future.set_exception(exc)
                with self.lock:self.items.pop(digest,None)
                raise
        result=copy.deepcopy(future.result());old=result.pop('path')
        for row in result['findings']+result['issues']:
            label=row.get('path','')
            if label==old or label.startswith(old+'!/'):row['path']=str(path)+label[len(old):]
        return result,not owner
