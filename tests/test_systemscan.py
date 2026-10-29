"""Coverage, cache integrity, live SQLite snapshots and binary record parsing."""
import json,os,sqlite3,struct,tempfile,threading,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from atlasac.cpubudget import ScanControl
from atlasac.engine import load_rules
from atlasac.paths import RULES
from atlasac.systemscan import system_scan
from atlasac.index import search_files
from atlasac.collectors import snapshot_database
from atlasac.winrecords import parse_usn,decode_prefetch

class SystemTests(unittest.TestCase):
    def setUp(self):
        # These tests check scope/cache integrity over 600 files, not CPU pacing.
        # Keep their runtime independent of the CI runner's reported core count.
        # The actual low-CPU pacing and cancellation test is test_cpubudget.py.
        pacing=patch('atlasac.systemscan.ScanControl',side_effect=lambda event:ScanControl(event,cores=1.0))
        pacing.start();self.addCleanup(pacing.stop)
    def test_full_scope_cache_and_changed_content_with_restored_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'disk';root.mkdir();cache=base/'state'
            for i in range(600):(root/f'ordinary-{i}.dat').write_text('normal file')
            target=root/'unrelated-folder';target.mkdir();sample=target/'a.dat'
            with zipfile.ZipFile(sample,'w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
            rules=load_rules(RULES)
            first=system_scan(rules,[root],data_dir=cache,artifacts=False)
            self.assertEqual(first['indexed_files'],601);self.assertEqual(len(first['findings']),1)
            self.assertEqual(len(search_files(first['index_path'],first['scan_id'])),500)
            second=system_scan(rules,[root],data_dir=cache,artifacts=False)
            self.assertEqual(second['cache_hits'],601)
            old=sample.stat();data=sample.read_bytes().replace(b'meteor-client',b'normal-client');sample.write_bytes(data)
            os.utime(sample,ns=(old.st_atime_ns,old.st_mtime_ns))
            third=system_scan(rules,[root],data_dir=cache,artifacts=False)
            self.assertLess(third['cache_hits'],601);self.assertFalse(third['findings'])
            rules=dict(rules,version=rules['version']+'-test')
            fourth=system_scan(rules,[root],data_dir=cache,artifacts=False)
            self.assertEqual(fourth['cache_hits'],0)
            self.assertFalse(search_files(first['index_path'],fourth['scan_id'],'%'))
    def test_cancellation_and_empty_disks_are_never_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cancel=threading.Event();cancel.set()
            self.assertEqual(system_scan(load_rules(RULES),[Path(tmp)],cancel,data_dir=Path(tmp)/'state',artifacts=False)['status'],'cancelled')
            result=system_scan(load_rules(RULES),[],data_dir=Path(tmp)/'state',artifacts=False)
            self.assertEqual(result['status'],'partial');self.assertIn('finished_at',result)
    def test_live_wal_snapshot_reads_committed_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'History';db=sqlite3.connect(path)
            try:
                db.execute('PRAGMA journal_mode=WAL');db.execute('CREATE TABLE urls(url TEXT)')
                db.execute('INSERT INTO urls VALUES(?)',('https://example.invalid/fixture',));db.commit()
                temp,snapshot=snapshot_database(path,threading.Event())
                try:
                    copy=sqlite3.connect(snapshot)
                    try:self.assertEqual(copy.execute('SELECT count(*) FROM urls').fetchone()[0],1)
                    finally:copy.close()
                finally:temp.cleanup()
                self.assertEqual(db.execute('SELECT count(*) FROM urls').fetchone()[0],1)
            finally:db.close()
    def test_exclusive_browser_lock_uses_consistent_private_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'History';db=sqlite3.connect(path)
            try:
                db.execute('PRAGMA locking_mode=EXCLUSIVE')
                db.execute('CREATE TABLE urls(url TEXT)');db.execute("INSERT INTO urls VALUES('committed')");db.commit()
                db.execute('BEGIN EXCLUSIVE')
                temp,snapshot=snapshot_database(path,threading.Event(),timeout=.02)
                try:
                    copy=sqlite3.connect(snapshot)
                    try:self.assertEqual(copy.execute('SELECT url FROM urls').fetchone()[0],'committed')
                    finally:copy.close()
                finally:temp.cleanup()
                db.rollback()
            finally:db.close()
    def test_usn_versions_and_malformed_bounds(self):
        for version,minimum,width in [(2,60,8),(3,76,16)]:
            name='sample.jar'.encode('utf-16-le');record=bytearray(minimum+len(name))
            struct.pack_into('<IHH',record,0,len(record),version,0)
            struct.pack_into('<qQI',record,8+width*2,42,133000000000000000,0x100)
            struct.pack_into('<HH',record,minimum-4,len(name),minimum);record[minimum:]=name
            parsed=parse_usn(b'\0'*8+record,'C:');self.assertEqual(parsed[0]['name'],'sample.jar')
            struct.pack_into('<H',record,minimum-2,len(record)+10)
            with self.assertRaises(ValueError):parse_usn(b'\0'*8+record)
    def test_prefetch_header(self):
        data=bytearray(256);struct.pack_into('<I',data,0,30);data[4:8]=b'SCCA'
        name='APP.EXE'.encode('utf-16-le');data[16:16+len(name)]=name
        struct.pack_into('<Q',data,128,133000000000000000)
        result=decode_prefetch(data);self.assertEqual(result['name'],'APP.EXE');self.assertEqual(len(result['recorded_run_times']),1)
    def test_live_events_preserve_all_matches_in_cold_and_cached_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'disk';root.mkdir();cache=Path(tmp)/'state'
            for i in range(3):
                with zipfile.ZipFile(root/f'{i}.dat','w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
            for _ in range(2):
                events=[];r=system_scan(load_rules(RULES),[root],data_dir=cache,artifacts=False,progress=events.append)
                live=[row for e in events for row in e['new_findings']]
                self.assertEqual(len(live),3)
                self.assertEqual({x['path'] for x in live},{x['path'] for x in r['findings']})
                self.assertEqual(events[-1]['content_files'],3)
                self.assertEqual(events[-1]['indexed'],3)
                self.assertTrue(all(len(e['recent_files'])<=160 for e in events))
