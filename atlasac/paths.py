"""Local resources and visible scan scope. No network services."""
import os
from pathlib import Path
import sys

BASE = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]))
ASSETS = BASE / 'atlasac' / 'web' / 'assets'
RULES = BASE / 'rules' / 'default.json'


def default_roots():
    home = Path.home()
    if os.name == 'nt':
        roaming = Path(os.environ.get('APPDATA', home / 'AppData/Roaming'))
        local = Path(os.environ.get('LOCALAPPDATA', home / 'AppData/Local'))
        candidates = [roaming / '.minecraft', roaming / 'PrismLauncher/instances',
                      local / 'Programs/PrismLauncher/instances', roaming / 'MultiMC/instances']
    else:
        candidates = [home / '.minecraft', home / '.local/share/PrismLauncher/instances',
                      home / '.var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/instances',
                      home / '.local/share/multimc/instances']
    candidates += [home / 'Downloads']
    return unique_roots(p for p in candidates if p.is_dir())


def unique_roots(paths):
    roots = sorted({Path(p).expanduser().resolve() for p in paths}, key=lambda p: len(p.parts))
    result = []
    for p in roots:
        if not any(p.is_relative_to(parent) for parent in result):
            result.append(p)
    return result
