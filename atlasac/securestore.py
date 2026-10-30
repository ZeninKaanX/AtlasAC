"""Private local storage. Fail rather than silently write data with unprotected permissions."""
from functools import lru_cache
from pathlib import Path
import json,os,stat,uuid
from .privacy import sanitize


def check_plain(path):
    path=Path(path)
    if path.is_symlink() or (path.exists() and getattr(path.lstat(),'st_file_attributes',0)&0x400):
        raise OSError('Kayıt yolu bağlantı / yeniden yönlendirme olamaz: '+str(path))
    return path


@lru_cache(maxsize=1)
def current_sid():
    import ctypes as c
    from ctypes import wintypes as w
    kernel=c.WinDLL('kernel32',use_last_error=True);adv=c.WinDLL('advapi32',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE
    adv.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)];adv.OpenProcessToken.restype=w.BOOL
    adv.GetTokenInformation.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)];adv.GetTokenInformation.restype=w.BOOL
    adv.ConvertSidToStringSidW.argtypes=[c.c_void_p,c.POINTER(w.LPWSTR)];adv.ConvertSidToStringSidW.restype=w.BOOL
    kernel.LocalFree.argtypes=[c.c_void_p];kernel.CloseHandle.argtypes=[w.HANDLE]
    token=w.HANDLE();length=w.DWORD();sid=w.LPWSTR()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,c.byref(token)):raise c.WinError(c.get_last_error())
    try:
        adv.GetTokenInformation(token,1,None,0,c.byref(length));buf=c.create_string_buffer(length.value)
        if not adv.GetTokenInformation(token,1,buf,length,c.byref(length)):raise c.WinError(c.get_last_error())
        pointer=c.cast(buf,c.POINTER(c.c_void_p))[0]
        if not adv.ConvertSidToStringSidW(pointer,c.byref(sid)):raise c.WinError(c.get_last_error())
        try:return sid.value
        finally:kernel.LocalFree(c.cast(sid,c.c_void_p))
    finally:kernel.CloseHandle(token)


def private_permissions(path):
    path=check_plain(path)
    if os.name!='nt':
        if path.stat().st_uid!=os.geteuid():raise PermissionError('Kayıt yolu bu kullanıcıya ait değil: '+str(path))
        path.chmod(0o700 if path.is_dir() else 0o600);return
    import ctypes as c
    from ctypes import wintypes as w
    adv=c.WinDLL('advapi32',use_last_error=True);kernel=c.WinDLL('kernel32',use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.POINTER(w.DWORD)]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=w.BOOL
    adv.GetSecurityDescriptorDacl.argtypes=[c.c_void_p,c.POINTER(w.BOOL),c.POINTER(c.c_void_p),c.POINTER(w.BOOL)];adv.GetSecurityDescriptorDacl.restype=w.BOOL
    adv.SetNamedSecurityInfoW.argtypes=[w.LPWSTR,c.c_int,w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p];adv.SetNamedSecurityInfoW.restype=w.DWORD
    kernel.LocalFree.argtypes=[c.c_void_p]
    flags='OICI' if path.is_dir() else ''
    sddl=f'D:P(A;{flags};FA;;;{current_sid()})(A;{flags};FA;;;SY)'
    descriptor=c.c_void_p();acl=c.c_void_p();present=w.BOOL();default=w.BOOL()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,c.byref(descriptor),None):raise c.WinError(c.get_last_error())
    try:
        if not adv.GetSecurityDescriptorDacl(descriptor,c.byref(present),c.byref(acl),c.byref(default)) or not present.value or not acl.value:raise OSError('Özel DACL oluşturulamadı')
        code=adv.SetNamedSecurityInfoW(str(path.resolve()),1,0x80000004,None,None,acl,None)
        if code:raise c.WinError(code)
    finally:kernel.LocalFree(descriptor)


def private_directory(path):
    path=check_plain(path)
    # Reject existing redirected parents, including Windows junctions.
    for parent in path.parents:
        if parent.exists():check_plain(parent)
    path.mkdir(parents=True,exist_ok=True,mode=0o700);private_permissions(path)
    return path


def write_json(path,data):
    path=check_plain(path);check_plain(path.parent)
    temporary=path.parent/('.atlasac-'+uuid.uuid4().hex+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        try:private_permissions(temporary)
        except BaseException:os.close(fd);raise
        with os.fdopen(fd,'w',encoding='utf-8') as stream:json.dump(sanitize(data),stream,ensure_ascii=False,indent=2)
        temporary.replace(path);private_permissions(path)
    finally:temporary.unlink(missing_ok=True)
