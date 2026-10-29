import json,tempfile,threading,unittest,zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from atlasac.contentcache import ContentCache
from atlasac.fileprobe import probe
from atlasac.engine import load_rules,inspect_archive
from atlasac.paths import RULES

class ContentCacheTests(unittest.TestCase):
    def test_hash_verified_copies_preserve_all_paths_and_read_archive_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=[root/(str(i)+'.jar') for i in range(8)]
            with zipfile.ZipFile(paths[0],'w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
            for p in paths[1:]:p.write_bytes(paths[0].read_bytes())
            cache=ContentCache();rules=load_rules(RULES)
            with patch('atlasac.fileprobe.inspect_archive',wraps=inspect_archive) as reader:
                with ThreadPoolExecutor(max_workers=4) as ex:results=list(ex.map(lambda p:probe(p,rules,threading.Event(),content_cache=cache),paths))
                self.assertEqual(reader.call_count,1)
            self.assertEqual(sum(r['archive_reused'] for r in results),7)
            for p,r in zip(paths,results):
                self.assertEqual(r['findings'][0]['path'],str(p));self.assertEqual(r['findings'][0]['rule'],'meteor');self.assertFalse(r['issues'])
            # Different bytes must not inherit a previous positive or negative result.
            with zipfile.ZipFile(paths[-1],'w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'sodium'}))
            self.assertFalse(probe(paths[-1],rules,threading.Event(),content_cache=cache)['findings'])

    def test_changed_file_cannot_publish_a_digest_cache_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a.jar';b=Path(tmp)/'b.jar'
            with zipfile.ZipFile(a,'w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
            b.write_bytes(a.read_bytes());cache=ContentCache();rules=load_rules(RULES)
            def mutate(*args,**kwargs):
                inspect_archive(*args,**kwargs)
                a.write_bytes(a.read_bytes()+b'changed during read')
            with patch('atlasac.fileprobe.inspect_archive',side_effect=mutate):result=probe(a,rules,threading.Event(),content_cache=cache)
            self.assertTrue(result['issues']);self.assertIsNone(result['fingerprint'])
            good=probe(b,rules,threading.Event(),content_cache=cache)
            self.assertFalse(good['archive_reused']);self.assertFalse(good['issues'])
            self.assertEqual(good['findings'][0]['rule'],'meteor')
