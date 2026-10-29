"""Ghost detection identities, benign lookalikes and native payload containers."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

from atlasac.engine import inspect_archive, load_rules, scan
from atlasac.fileprobe import probe
from atlasac.paths import RULES
from atlasac.systemscan import system_scan


class GhostTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.rules = load_rules(RULES)

    def tearDown(self):
        self.temp.cleanup()

    def archive(self, members):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as z:
            for name, data in members.items():
                z.writestr(name, data)
        return stream.getvalue()

    def native_rules(self, content):
        return dict(self.rules, rules=[{
            'id': 'fixture-native', 'name': 'Native test fixture', 'category': 'ghost-client',
            'source': 'fixture', 'mod_ids': [], 'class_prefixes': [],
            'file_signatures': [{'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}]
        }])

    def test_benign_metadata_names_do_not_impersonate_ghosts(self):
        for mod_id in ('immediatelyfast', 'argon', 'imnotcheatingyouare', 'vape', 'slinky', 'raven'):
            p = self.root / (mod_id + '.jar')
            p.write_bytes(self.archive({'fabric.mod.json': json.dumps({'id': mod_id})}))
        self.assertFalse(scan(self.root, self.rules)['findings'])

    def test_argon_requires_all_specific_classes_not_benign_metadata(self):
        rule = next(r for r in self.rules['rules'] if r['id'] == 'argon')
        p = self.root / 'ImmediatelyFast.jar'
        members = {n: b'fixture' for n in rule['required_classes']}
        members['fabric.mod.json'] = '{"id":"immediatelyfast"}'
        members['icon.png'] = b'\x89PNG\r\n\x1a\n' + b'benign-mod-icon'
        for count in (1, 2, 3):
            subset = {k: v for k, v in members.items() if k not in rule['required_classes'][count:]}
            p.write_bytes(self.archive(subset))
            result = probe(p, self.rules, threading.Event())
            self.assertEqual(bool(result['findings']), count == 3)
            if count == 3:
                finding = result['findings'][0]
                self.assertEqual(finding['rule'], 'argon')
                self.assertNotIn('icon_png_base64', finding)

    def test_native_exact_bytes_and_size_renamed_and_changed(self):
        content = b'MZ' + b'controlled native fixture' * 30
        rules = self.native_rules(content)
        target = self.root / 'unrelated.tmp'
        target.write_bytes(content)
        result = probe(target, rules, threading.Event())
        self.assertEqual(result['findings'][0]['method'], 'file-sha256')
        self.assertEqual(scan(self.root, rules)['findings'][0]['rule'], 'fixture-native')
        for changed in (content[:-1] + b'X', content + b'X'):
            target.write_bytes(changed)
            self.assertFalse(probe(target, rules, threading.Event())['findings'])

    def test_unrelated_native_sizes_do_not_trigger_full_hashing(self):
        content = b'MZ' + b'known' * 10
        target = self.root / 'large.dll'
        target.write_bytes(b'MZ' + bytes(1024 * 1024))
        rules = self.native_rules(content)
        with patch('atlasac.fileprobe.hashlib.sha256', side_effect=AssertionError('Unexpected full read')):
            result = probe(target, rules, threading.Event())
        self.assertIsNone(result['file']['sha256'])

    def test_nested_native_payload_preserves_evidence_path(self):
        content = b'MZ' + b'controlled fixture' * 10
        rules = self.native_rules(content)
        inner = self.archive({'payload/random.bin': content})
        findings = []; issues = []
        inspect_archive(io.BytesIO(self.archive({'inner.jar': inner})), 'renamed.zip', rules, findings, issues)
        self.assertFalse(issues)
        self.assertEqual(findings[0]['path'], 'renamed.zip!/inner.jar!/payload/random.bin')

    def test_native_live_results_and_cache_invalidation(self):
        content = b'MZ' + b'controlled fixture' * 10
        rules = self.native_rules(content)
        disk = self.root / 'disk'; disk.mkdir()
        target = disk / 'unknown.dll'; target.write_bytes(content)
        for _ in range(2):
            events = []
            r = system_scan(rules, [disk], data_dir=self.root/'state', artifacts=False, progress=events.append)
            self.assertEqual(len(r['findings']), 1)
            self.assertEqual([f for e in events for f in e['new_findings']], r['findings'])
        changed_rules = dict(rules, rules=[dict(rules['rules'][0], file_signatures=[])])
        r = system_scan(changed_rules, [disk], data_dir=self.root/'state', artifacts=False)
        self.assertFalse(r['findings'])

    def test_invalid_native_signatures_rejected(self):
        content = b'MZfixture'
        for signature in ({'size': True, 'sha256': 'a'*64}, {'size': 0, 'sha256': 'a'*64},
                          {'size': 1, 'sha256': 'z'*64}, {'size': 1}, 'not-a-dict'):
            rules = self.native_rules(content); rules['rules'][0]['file_signatures'] = [signature]
            p = self.root/'rules.json'; p.write_text(json.dumps(rules))
            with self.assertRaises(ValueError): load_rules(p)
