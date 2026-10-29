import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch
from atlasac.engine import load_rules, scan

RULES = load_rules(Path(__file__).resolve().parents[1] / 'rules/default.json')


def jar(path, members):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for k, v in members.items():
            z.writestr(k, v)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def test_renamed_mod_detected_by_metadata(self):
        jar(self.root / 'sodium.jar', {'fabric.mod.json': json.dumps({'id':'meteor-client'})})
        r = scan(self.root, RULES)
        self.assertEqual(r['findings'][0]['name'], 'Meteor Client')
        self.assertEqual(r['findings'][0]['method'], 'mod-id')
        self.assertEqual(len(r['files'][0]['sha256']), 64)
    def test_filename_and_generic_mixin_do_not_flag(self):
        jar(self.root / 'wurst-clicker.jar', {'fabric.mod.json':'{"id":"sodium"}', 'mixins.json':'{"package":"legit"}', 'net/wurstclient/readme.txt':'documentation'})
        self.assertFalse(scan(self.root, RULES)['findings'])
    def test_nested_jar_and_no_extraction(self):
        buf = io.BytesIO()
        jar(buf, {'fabric.mod.json':'{"id":"liquidbounce"}'})
        jar(self.root / 'wrapper.jar', {'../nested.jar':buf.getvalue()})
        r = scan(self.root, RULES)
        self.assertEqual(r['findings'][0]['path'], 'wrapper.jar!/../nested.jar')
        self.assertEqual(len(list(self.root.iterdir())), 1)
    def test_corrupt_archive_is_partial(self):
        (self.root / 'broken.jar').write_bytes(b'bad zip')
        r = scan(self.root, RULES)
        self.assertEqual(r['status'], 'partial')
        self.assertTrue(r['issues'])
    def test_forge_metadata(self):
        jar(self.root / 'forge.jar', {'META-INF/mods.toml':'[[mods]]\nmodId="baritone"\nversion="1"'})
        r = scan(self.root, RULES)
        self.assertEqual(r['findings'][0]['severity'], 'review')
    def test_quilt(self):
        jar(self.root / 'quilt.jar', {'quilt.mod.json':'{"quilt_loader":{"id":"meteor-client"}}'})
        self.assertEqual(scan(self.root, RULES)['findings'][0]['method'], 'mod-id')
    def test_namespace_requires_two_class_members(self):
        jar(self.root / 'classes.jar', {'net/wurstclient/A.class': b'a', 'net/wurstclient/B.class':b'b'})
        self.assertEqual(scan(self.root, RULES)['findings'][0]['method'], 'class-namespace')
    def test_cancelled_and_limits_not_clean(self):
        (self.root / 'a.jar').write_bytes(b'a')
        cancel = threading.Event(); cancel.set()
        self.assertEqual(scan(self.root, RULES, cancel)['status'], 'cancelled')
        with patch('atlasac.engine.MAX_FILE', 0):
            self.assertEqual(scan(self.root, RULES)['status'], 'partial')
    def test_symlink_skipped(self):
        try:
            (self.root / 'escape.jar').symlink_to('/etc/passwd')
        except OSError:
            self.skipTest('No symlink permission')
        r = scan(self.root, RULES)
        self.assertEqual(r['files'], [])
        self.assertEqual(r['status'], 'partial')
    def test_metadata_limit(self):
        jar(self.root / 'huge.jar', {'fabric.mod.json':' ' * 1000})
        with patch('atlasac.engine.MAX_MEMBER', 10):
            r = scan(self.root, RULES)
            self.assertEqual(r['status'], 'partial')
    def test_every_bundled_mod_id_is_matched(self):
        for rule in RULES['rules']:
            if not rule['mod_ids']:
                continue
            with self.subTest(rule=rule['id']):
                path = self.root / 'renamed.jar'
                jar(path, {'fabric.mod.json': json.dumps({'id':rule['mod_ids'][0]})})
                self.assertEqual(scan(self.root, RULES)['findings'][0]['rule'], rule['id'])

    def test_archive_disguised_as_text_is_inspected(self):
        jar(self.root / 'innocent.txt', {'fabric.mod.json':'{"id":"thunderhack"}'})
        r = scan(self.root, RULES)
        self.assertEqual(r['findings'][0]['name'], 'ThunderHack')
        self.assertEqual(r['files'][0]['format'], 'ZIP')

    def test_legacy_forge_metadata(self):
        jar(self.root / 'forge.jar', {'mcmod.info':'[{"modid":"fdpclient","name":"FDPClient"}]'})
        r = scan(self.root, RULES)
        self.assertEqual(r['findings'][0]['rule'], 'fdpclient')

    def test_nested_jar_disguised_with_bin_extension(self):
        buf = io.BytesIO()
        jar(buf, {'fabric.mod.json':'{"id":"meteor-client"}'})
        jar(self.root / 'wrapper.zip', {'payload.bin':buf.getvalue()})
        self.assertEqual(scan(self.root, RULES)['findings'][0]['rule'], 'meteor')

    def test_zip_overlay_with_image_header(self):
        buf = io.BytesIO()
        jar(buf, {'fabric.mod.json':'{"id":"wurst"}'})
        (self.root / 'image.png').write_bytes(b'\x89PNG\r\n\x1a\n' + buf.getvalue())
        r = scan(self.root, RULES)
        self.assertEqual(r['findings'][0]['rule'], 'wurst')
        self.assertEqual(r['files'][0]['format'], 'ZIP-overlay')

    def test_invalid_class_with_marker_is_reported_incomplete(self):
        jar(self.root / 'malformed.jar', {'Some.class':b'hacktheserver'})
        r = scan(self.root, RULES)
        self.assertEqual(r['status'], 'partial')
        self.assertFalse(r['findings'])

    def test_duplicate_archive_entry_is_not_two_distinct_classes(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            with zipfile.ZipFile(self.root/'duplicate.jar', 'w') as z:
                z.writestr('meteordevelopment/meteorclient/Only.class', b'inert')
                z.writestr('meteordevelopment/meteorclient/Only.class', b'inert')
        self.assertFalse(scan(self.root, RULES)['findings'])

    def test_class_signature_requires_every_exact_class(self):
        required = next(r['required_classes'] for r in RULES['rules'] if r['id']=='cigarette')
        jar(self.root/'one.jar', {required[0]:b'inert', 'io/github/waqfs/unrelated/Other.class':b'inert'})
        result = scan(self.root, RULES)
        self.assertFalse(result['findings'])
        (self.root/'one.jar').unlink()
        jar(self.root/'two.jar', {name:b'inert' for name in required})
        result = scan(self.root, RULES)
        self.assertEqual(result['findings'][0]['rule'], 'cigarette')
        self.assertEqual(result['findings'][0]['method'], 'class-signature')

    def test_named_liquidbounce_derivative_is_not_double_labelled(self):
        jar(self.root/'fork.jar', {'mcmod.info': json.dumps([{'modid':'crosssine'}]),
            'net/ccbluex/liquidbounce/A.class':b'inert', 'net/ccbluex/liquidbounce/B.class':b'inert'})
        self.assertEqual([r['rule'] for r in scan(self.root, RULES)['findings']], ['crosssine'])

    def test_invalid_exact_class_signature_rejected(self):
        data = dict(RULES, rules=[dict(RULES['rules'][0], required_classes=['Only.class'])])
        path = self.root/'invalid.json';path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):load_rules(path)

    def test_hash_rule(self):
        import hashlib
        b = b'fixture'; (self.root/'test.exe').write_bytes(b)
        rules = dict(RULES, hashes={hashlib.sha256(b).hexdigest():'Test signature'})
        self.assertEqual(scan(self.root, rules)['findings'][0]['method'], 'sha256')

if __name__ == '__main__':
    unittest.main()


class PrefixLookupTests(unittest.TestCase):
    def test_overlapping_prefixes_preserve_distinct_hit_threshold_and_first_four(self):
        import io,zipfile
        from atlasac.engine import inspect_archive
        names=['a/one.class','a/sub/three.class','a/sub/two.class','a/z.class','a/zz.class','b/normal.class']
        rules={'rules':[{'id':'prefix','name':'prefix','category':'client','source':'fixture','mod_ids':[],'class_prefixes':['a/','a/sub/']}],'hashes':{}}
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            for name in reversed(names):z.writestr(name,b'\xca\xfe\xba\xbe')
        stream.seek(0);findings=[];issues=[];inspect_archive(stream,'fixture',rules,findings,issues)
        self.assertEqual(findings[0]['evidence'],sorted(n for n in names if n.startswith('a/'))[:4])
        self.assertFalse(issues)

class MemberSignatureTests(unittest.TestCase):
    def test_member_hashes_survive_repacking_but_not_same_names_with_other_content(self):
        import io,zipfile,hashlib
        from atlasac.engine import inspect_archive
        blobs={'net/java/f.class':b'fixture-one','net/java/n.class':b'fixture-two'}
        rule={'id':'fixture-ghost','name':'fixture','category':'ghost-client','source':'fixture','mod_ids':[],'class_prefixes':[],'required_member_sha256':{n:hashlib.sha256(b).hexdigest() for n,b in blobs.items()}}
        rules={'rules':[rule],'hashes':{}}
        for changed in (False,True):
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:
                for n,b in blobs.items():z.writestr(n,b+(b'other' if changed else b''))
                z.writestr('padding.bin',b'padding')
            stream.seek(0);findings=[];issues=[];inspect_archive(stream,'renamed-fixture',rules,findings,issues)
            self.assertFalse(issues)
            self.assertEqual(len(findings),0 if changed else 1)
            if findings:self.assertEqual(findings[0]['method'],'member-sha256')
