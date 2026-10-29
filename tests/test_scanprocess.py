import tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from atlasac.engine import load_rules
from atlasac.paths import RULES
from atlasac.scanprocess import run_scan
from atlasac.systemscan import system_scan


def stalled_child(messages,cancel,rules,roots,data_dir,artifacts):
    messages.put(('progress',{'phase':'test','path':'','indexed':1,'matches':0,'elapsed':0,'new_findings':[],'recent_files':[],'internal_exclusions':['owned-resource'],'scope_note':'candidate scope','limits':['test limit'],'artifact_snapshot':{'commands':[{'command':'echo fixture','kind':'history'}]},'components':[{'name':'command fixture','status':'partial'}]}))
    time.sleep(30)

class ProcessTests(unittest.TestCase):
    def test_hard_budget_terminates_unresponsive_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            events=[];start=time.monotonic()
            report=run_scan(load_rules(RULES),[Path(tmp)],Path(tmp)/'state',False,threading.Event(),events.append,max_seconds=1.5,target=stalled_child)
            self.assertLess(time.monotonic()-start,3)
            self.assertEqual(report['stop_reason'],'time_budget');self.assertEqual(report['status'],'partial')
            self.assertTrue(events);self.assertTrue(report['partial_snapshot'])
            self.assertEqual(report['artifacts']['commands'][0]['command'],'echo fixture')
            self.assertEqual(report['components'][0]['name'],'command fixture')
            self.assertEqual(report['internal_exclusions'],['owned-resource']);self.assertEqual(report['scope_note'],'candidate scope')
    def test_excluded_library_does_not_hide_other_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();skip=root/'games';skip.mkdir();(skip/'game.dat').write_text('game');(root/'other.dat').write_text('scan')
            with patch('atlasac.systemscan.excluded_locations',return_value={skip:'Oyun kütüphanesi'}):
                report=system_scan(load_rules(RULES),[root],data_dir=root/'state',artifacts=False)
            self.assertEqual(report['indexed_files'],1);self.assertEqual(report['excluded_paths'],[str(skip)])

    def test_all_jars_survive_library_filter_and_images_are_skipped(self):
        import json,zipfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();games=root/'library';games.mkdir()
            for p in (games/'client.JAR',root/'client.jar'):
                with zipfile.ZipFile(p,'w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
            for p in (games/'game.png',root/'picture.png',games/'game.exe',root/'readme.md'):p.write_bytes(b'normal')
            with patch('atlasac.systemscan.excluded_locations',return_value={games:'Oyun kütüphanesi'}):
                report=system_scan(load_rules(RULES),[root],data_dir=root/'state',artifacts=False)
            self.assertEqual(report['indexed_files'],2)
            self.assertEqual(report['ignored_files'],4)
            self.assertEqual(len(report['findings']),2)

    def test_only_running_frozen_resource_directory_is_excluded(self):
        import sys,json,zipfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();internal=root/'_MEI-active';internal.mkdir()
            for path in (internal/'inside.jar',root/'real-mod.jar'):
                with zipfile.ZipFile(path,'w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
            with patch.object(sys,'frozen',True,create=True),patch.object(sys,'_MEIPASS',str(internal),create=True):
                events=[];report=system_scan(load_rules(RULES),[root],data_dir=root/'state',artifacts=False,progress=events.append)
            self.assertIn(str(internal),events[-1]['internal_exclusions'])
            self.assertEqual(report['indexed_files'],1)
            self.assertEqual(report['findings'][0]['path'],str(root/'real-mod.jar'))
            self.assertIn(str(internal),report['internal_exclusions'])
