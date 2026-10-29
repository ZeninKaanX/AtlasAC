import tempfile
from pathlib import Path
import unittest
from atlasac.reports import ReportHistory
from atlasac.paths import unique_roots

class ReportTests(unittest.TestCase):
    def test_local_history_roundtrip_and_bounded_retention(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = ReportHistory(tmp)
            report = dict(started_at='2026-10-29T00:00:00Z', status='partial', roots=['/mods'], findings=[], files=[], issues=[{'reason':'limit'}])
            for _ in range(52):
                history.save(report)
            self.assertEqual(len(history.paths()), 50)
            self.assertEqual(history.read(history.paths()[0]), report)
            self.assertFalse(list(Path(tmp).glob('*.tmp')))

    def test_history_rejects_outside_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                ReportHistory(Path(tmp)/'history').read(Path(tmp)/'outside.json')

    def test_roots_are_deduplicated_without_losing_siblings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            self.assertCountEqual(unique_roots([root/'a',root/'a/mods',root/'b',root/'a']),[root/'a',root/'b'])
