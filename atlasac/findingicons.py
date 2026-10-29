"""Read bounded, embedded PNG icons without extracting or executing a file."""
import base64
import io
import json
import tomllib
import zipfile
import zlib

MAX_ICON=512*1024

def embedded_icon(stream,label):
    """Follow an already detected nested archive path; all work stays in the scan child."""
    try:
        stream.seek(0)
        with zipfile.ZipFile(stream) as archive:
            parts=label.split('!/',1)
            if len(parts)>1:
                inner,_,rest=parts[1].partition('!/')
                if inner.lower().endswith(('.jar','.zip')):
                    info=archive.getinfo(inner)
                    if info.file_size>32*1024*1024:return None
                    return embedded_icon(io.BytesIO(archive.read(info)),inner+('!/'+rest if rest else ''))
                return None
            names=[]
            for name in ('fabric.mod.json','quilt.mod.json','mcmod.info','META-INF/mods.toml','META-INF/neoforge.mods.toml'):
                try:
                    info=archive.getinfo(name)
                    if info.file_size>MAX_ICON:continue
                    raw=archive.read(info)
                    meta=tomllib.loads(raw.decode()) if name.endswith('.toml') else json.loads(raw)
                    if name=='quilt.mod.json':meta=meta.get('quilt_loader',{}).get('metadata',{})
                    mods=meta if isinstance(meta,list) else meta.get('mods',meta.get('modList',[meta]))
                    for mod in mods:
                        if not isinstance(mod,dict):continue
                        icon=mod.get('icon') or mod.get('logoFile')
                        if isinstance(icon,dict):icon=next(iter(icon.values()),None)
                        if isinstance(icon,str):names.append(icon)
                except (KeyError,ValueError,TypeError,AttributeError,UnicodeError):continue
            names+=['icon.png','logo.png','pack.png']
            for name in names[:16]:
                if not name.lower().endswith('.png'):continue
                try:
                    info=archive.getinfo(name)
                    if 8<info.file_size<=MAX_ICON:
                        data=archive.read(info)
                        if data.startswith(b'\x89PNG\r\n\x1a\n'):return base64.b64encode(data).decode('ascii')
                except KeyError:continue
    except (OSError,ValueError,RuntimeError,NotImplementedError,zlib.error,zipfile.BadZipFile):pass
    return None
