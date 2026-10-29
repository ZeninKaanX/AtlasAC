"""Bounded local JSON history, independent from the graphical interface."""
import json
import os
from pathlib import Path
import uuid


class ReportHistory:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else Path.home() / '.atlasac' / 'reports'

    def save(self, report):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = report['started_at'].replace(':', '-').replace('/', '-') + '-' + uuid.uuid4().hex[:8]
        target = self.directory / (name + '.json')
        temporary = self.directory / (name + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            temporary.replace(target)
        finally:
            temporary.unlink(missing_ok=True)
        for old in self.paths()[50:]:
            old.unlink()
        return target

    def paths(self):
        return sorted(self.directory.glob('*.json'), reverse=True) if self.directory.exists() else []

    def read(self, path):
        path = Path(path)
        if path.parent.resolve() != self.directory.resolve() or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('Geçersiz rapor yolu veya boyutu')
        report = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(report, dict) or not all(k in report for k in ('started_at', 'status', 'roots', 'findings', 'files', 'issues')):
            raise ValueError('Geçersiz rapor')
        return report
