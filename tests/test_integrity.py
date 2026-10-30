import copy,json,tempfile,threading,unittest,zipfile,sqlite3
from pathlib import Path
from unittest.mock import patch
from atlasac import __version__
from atlasac.engine import load_rules
from atlasac.paths import RULES
from atlasac.integrity import rules_digest,require_official_rules,validate_packet,attach_receipt,verify_receipt
from atlasac.scanprocess import run_scan
from atlasac.systemscan import system_scan
from atlasac.fileprobe import probe
from atlasac.reports import ReportHistory
from atlasac.reveal import verdict_for


def observed_finding(root):return {'rule':'meteor','name':'Meteor Client','path':str(root/'client.jar'),'method':'mod-id','evidence':['meteor-client']}


def progress_with_finding(messages,root):
    messages.put(('progress',{'phase':'fixture','path':str(root),'indexed':1,'matches':1,'elapsed':0,'new_findings':[observed_finding(root)],'recent_files':[]}))


def dropped_final(messages,cancel,rules,roots,data_dir,artifacts):
    root=Path(roots[0]).resolve();progress_with_finding(messages,root)
    messages.put(('ready',{'application':'AtlasAC','version':__version__,'rule_version':rules['version'],'roots':[str(root)],'status':'completed','findings':[],'files':[],'issues':[],'artifacts':{},'components':[],'indexed_files':1,'content_files':1,'ignored_files':0,'issues_total':0}))


def malformed_after_finding(messages,cancel,rules,roots,data_dir,artifacts):
    root=Path(roots[0]).resolve();progress_with_finding(messages,root)
    messages.put(('progress',{'phase':'fixture','path':str(root),'indexed':1,'matches':1,'new_findings':[],'artifact_snapshot':'bad'}))


class IntegrityTests(unittest.TestCase):
    def test_rules_changes_rejected_but_formatting_is_not_an_alarm(self):
        rules=load_rules(RULES);require_official_rules(rules)
        changed=copy.deepcopy(rules);changed['rules']=[]
        with self.assertRaises(ValueError):require_official_rules(changed)
        self.assertEqual(rules_digest(rules),rules_digest(json.loads(json.dumps(rules,indent=5))))
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'bad.json';p.write_text('{"rules":[],"rules":[],"hashes":{}}')
            with self.assertRaises(ValueError):load_rules(p)

    def test_session_replay_sequence_gap_and_wrong_nonce_are_rejected(self):
        packet={'session':'current','sequence':1,'kind':'progress','data':{}}
        self.assertEqual(validate_packet(packet,'current',1)[0],'progress')
        for session,sequence in [('previous',1),('current',2)]:
            with self.assertRaises(ValueError):validate_packet(packet,session,sequence)
        with self.assertRaises(ValueError):validate_packet(('ready',{}),'current',1)

    def test_file_and_sqlite_cache_poisoning_cannot_hide_real_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'disk';root.mkdir();path=root/'client.jar'
            with zipfile.ZipFile(path,'w') as z:z.writestr('fabric.mod.json','{"id":"meteor-client"}')
            rules=load_rules(RULES);first=probe(path,rules,threading.Event())
            forged=copy.deepcopy(first);forged['findings']=[]
            again=probe(path,rules,threading.Event(),cached=forged)
            self.assertEqual(again['findings'][0]['rule'],'meteor');self.assertFalse(again['cache_hit'])
            state=Path(tmp)/'state';report=system_scan(rules,[root],artifacts=False,data_dir=state)
            db=sqlite3.connect(report['index_path']);db.execute('UPDATE files SET cache=?',(json.dumps(forged),));db.commit();db.close()
            again=system_scan(rules,[root],artifacts=False,data_dir=state)
            self.assertEqual(again['findings'][0]['rule'],'meteor');self.assertEqual(again['cache_hits'],0)
            db=sqlite3.connect(report['index_path']);self.assertIsNone(db.execute('SELECT cache FROM files').fetchone()[0]);db.close()

    def test_dropped_live_match_and_malformed_progress_preserve_evidence(self):
        for target in (dropped_final,malformed_after_finding):
            with self.subTest(target=target.__name__),tempfile.TemporaryDirectory() as tmp:
                report=run_scan(load_rules(RULES),[Path(tmp)],Path(tmp)/'state',False,threading.Event(),lambda data:None,max_seconds=5,target=target)
                self.assertEqual(report['status'],'partial');self.assertFalse(report['integrity']['protocol_consistent'])
                self.assertEqual(report['findings'][0]['rule'],'meteor');self.assertNotEqual(verdict_for(report)[0],'Temiz')
                self.assertTrue(verify_receipt(report)['checksum_matches'])

    def test_report_edit_and_checksum_replacement_need_original_external_digest(self):
        report=attach_receipt({'status':'completed','findings':[]})
        original=report['report_receipt']['payload_sha256']
        self.assertTrue(verify_receipt(report,original)['checksum_matches'])
        modified=copy.deepcopy(report);modified['status']='partial'
        self.assertFalse(verify_receipt(modified)['checksum_matches'])
        # No embedded secret / fake signature: an owner CAN recompute a plain hash.
        forged=attach_receipt(modified)
        self.assertTrue(verify_receipt(forged)['checksum_matches'])
        self.assertFalse(verify_receipt(forged,original)['checksum_matches'])
        self.assertFalse(verify_receipt(forged)['host_verified'])

    def test_history_reader_rejects_edit_of_sealed_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            history=ReportHistory(tmp)
            report=attach_receipt(dict(started_at='2026-10-30T00:00:00Z',status='completed',roots=[],findings=[],files=[],issues=[]))
            path=history.save(report);self.assertEqual(history.read(path),report)
            changed=json.loads(path.read_text());changed['findings']=[{'rule':'fake'}];path.write_text(json.dumps(changed))
            history.maintain()
            with self.assertRaises(ValueError):history.read(path)

    def test_scope_counter_and_partial_coverage_cannot_be_upgraded_to_clean(self):
        from atlasac.integrity import checked_final
        from atlasac.engine import now
        with tempfile.TemporaryDirectory() as tmp:
            rules=load_rules(RULES)
            snapshot={'application':'AtlasAC','version':__version__,'rule_version':rules['version'],'roots':[tmp],'status':'running','findings':[],'files':[],'issues':[],'artifacts':{},'components':[{'name':'reader','status':'partial'}],'indexed_files':5,'content_files':2,'ignored_files':0,'issues_total':0}
            final=copy.deepcopy(snapshot);final.update(status='completed',roots=[],indexed_files=0,components=[])
            checked=checked_final(snapshot,final,rules,[Path(tmp)])
            self.assertEqual(checked['status'],'partial');self.assertFalse(checked['integrity']['protocol_consistent'])
            self.assertEqual(checked['components'],snapshot['components']);self.assertNotEqual(verdict_for(checked)[0],'Temiz')
