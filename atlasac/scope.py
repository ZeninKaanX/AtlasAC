"""Explicit scan exclusions requested by the user; directory names are not trust proof."""
from pathlib import Path
import os,re

def steam_libraries():
    home=Path.home()
    roots=[home/'.local/share/Steam',home/'.steam/steam',home/'.steam/root',home/'.var/app/com.valvesoftware.Steam/.local/share/Steam']
    if os.name=='nt':
        roots += [Path(os.environ.get('ProgramFiles(x86)','C:/Program Files (x86)'))/'Steam',Path(os.environ.get('ProgramFiles','C:/Program Files'))/'Steam']
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Valve\Steam') as key:roots.append(Path(winreg.QueryValueEx(key,'SteamPath')[0]))
        except OSError:pass
    libraries=[]
    for root in roots:
        if not root.is_dir():continue
        libraries.append(root/'steamapps')
        vdf=root/'steamapps/libraryfolders.vdf'
        try:
            if vdf.stat().st_size<=1024*1024:
                text=vdf.read_text(encoding='utf-8',errors='replace')
                for value in re.findall(r'"path"\s+"([^"\r\n]+)"',text):libraries.append(Path(value.replace('\\\\','\\'))/'steamapps')
        except OSError:pass
    return sorted({p.resolve() for p in libraries if p.is_dir()},key=str)


def excluded_locations(include_development=True):
    """Known game-library/cache locations; exclusions are explicit scope choices."""
    import json
    home=Path.home();candidates={p:'Steam oyun kütüphanesi' for p in steam_libraries()}
    if os.name=='nt':
        import psutil
        drives=[Path(p.mountpoint) for p in psutil.disk_partitions(all=False) if p.fstype]
        for drive in drives:
            for name in ('XboxGames','Epic Games','SteamLibrary/steamapps','Riot Games','EA Games','Ubisoft Games'):
                candidates[drive/name]='Oyun kütüphanesi'
        for env,fallback in [('ProgramFiles','C:/Program Files'),('ProgramFiles(x86)','C:/Program Files (x86)')]:
            base=Path(os.environ.get(env,fallback))
            for name in ('Epic Games','EA Games','Origin Games','Ubisoft/Ubisoft Game Launcher/games','World of Warcraft','Diablo IV','Overwatch','Riot Games'):
                candidates[base/name]='Oyun kütüphanesi'
        manifests=Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'Epic/EpicGamesLauncher/Data/Manifests'
        for p in manifests.glob('*.item'):
            try:
                if p.stat().st_size<=1024*1024:
                    value=json.loads(p.read_text(encoding='utf-8-sig')).get('InstallLocation')
                    if isinstance(value,str):candidates[Path(value)]='Epic oyun kütüphanesi (yerel manifest)'
            except (OSError,ValueError):pass
    else:
        for name in ('Games/Heroic','Games/heroic','Games/Lutris','Games/lutris','.local/share/lutris/runners'):
            candidates[home/name]='Oyun kütüphanesi / launcher çalışma dosyaları'
    if include_development:
        for name in ('.gradle/caches','.gradle/wrapper/dists','.m2/repository','.cache/pip','.npm/_cacache','Android/Sdk'):
            candidates[home/name]='Geliştirme araçları önbelleği / SDK'
        for env in ('ANDROID_HOME','ANDROID_SDK_ROOT'):
            if os.environ.get(env):candidates[Path(os.environ[env])]='Android SDK'
        if os.name=='nt':
            local=Path(os.environ.get('LOCALAPPDATA',home/'AppData/Local'))
            for name in ('Android/Sdk','pip/Cache','npm-cache/_cacache'):candidates[local/name]='Geliştirme araçları önbelleği / SDK'
    result={}
    for path,reason in candidates.items():
        try:
            p=path.resolve()
            if p.is_dir() and len(p.parts)>=3 and p not in (home,home.parent):result[p]=reason
        except OSError:pass
    return result
