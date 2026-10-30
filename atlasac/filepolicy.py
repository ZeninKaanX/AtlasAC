"""Candidate extensions requested by the user; images/media/documents are skipped."""
ARCHIVES={'.jar','.zip'}
CANDIDATES=ARCHIVES|{'.exe','.dll','.sys','.scr','.com','.msi','.pyd','.so','.dylib','.appimage','.class',
    '.dat','.bin','.tmp','.cache','.ps1','.bat','.cmd','.vbs','.js','.py','.ahk','.lua'}

def candidate(path,archives_only=False):
    return candidate_name(path.name,archives_only)

def candidate_name(name,archives_only=False):
    dot=name.rfind('.')
    suffix=name[dot:].lower() if 0<dot<len(name)-1 else ''
    return suffix in ARCHIVES if archives_only else not suffix or suffix in CANDIDATES

def directory_priority(path,archives_only):
    if archives_only:return 50
    name=path.name.lower()
    if name in {'home','users','.minecraft','downloads','desktop','documents','appdata','roaming'}:return 0
    if name in {'windows','usr','opt','program files','program files (x86)','system32','winsxs'}:return 30
    return 10
