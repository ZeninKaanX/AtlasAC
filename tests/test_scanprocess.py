import tempfile,threading,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from atlasac.engine import load_rules
from atlasac.paths import RULES
from atlasac.scanprocess import run_scan
from atlasac.systemscan import system_scan


def stalled_child(messages,cancel,rules,roots,data_dir,artifacts):
    messages.put(('progress',{'phase':'test','path':'','indexed':1,'matches':0,'elapsed':0,'new_findings':[],'recent_files':[],'internal_exclusions':['owned-resource'],'scope_note':'candidate scope','limits':['test limit'],'artifact_snapshot':{'commands':[{'command':'echo fixture','kind':'history'}]},'components':[{'name':'command fixture','status':'partial'}]}))
    time.sleep(30)


def gated_scan_child(messages,cancel,rules,roots,data_dir,artifacts):
    def relay(data):
        messages.put(('progress',data))
        if data.get('new_findings'):
            while not (Path(data_dir)/'resume').exists():
                if cancel.wait(.01):break
    report=system_scan(rules,roots,cancel,relay,data_dir,artifacts)
    messages.put(('ready',report))

class ProcessTests(unittest.TestCase):
    def test_selected_speed_reaches_the_actual_scan_worker(self):
        from atlasac.cpubudget import cpu_target
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'disk';root.mkdir()
            report=run_scan(load_rules(RULES),[root],Path(tmp)/'state',False,threading.Event(),lambda data:None,speed='balanced')
            self.assertEqual(report['status'],'completed')
            self.assertEqual(report['scan_speed'],'balanced')
            self.assertAlmostEqual(report['cpu_target_cores'],cpu_target('balanced'))
            self.assertIsNone(report['time_budget_seconds'])
    def test_default_scan_survives_old_deadline_and_explicit_long_budget_is_honoured(self):
        import zipfile
        for limit,jump in ((None,7201),(7200,601)):
            with self.subTest(limit=limit),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);disk=root/'disk';disk.mkdir();state=root/'state'
                with zipfile.ZipFile(disk/'client.jar','w') as z:z.writestr('fabric.mod.json','{"id":"meteor-client"}')
                offset=[0.];events=[];cancel=threading.Event()
                real_clock=time.monotonic
                def progress(data):
                    events.append(data)
                    if data.get('new_findings'):
                        offset[0]=jump
                        (state/'resume').touch()
                watchdog=threading.Timer(10,cancel.set);watchdog.start()
                try:
                    with patch('atlasac.scanprocess.time',SimpleNamespace(monotonic=lambda:real_clock()+offset[0])):
                        kwargs={} if limit is None else {'max_seconds':limit}
                        report=run_scan(load_rules(RULES),[disk],state,False,cancel,progress,target=gated_scan_child,**kwargs)
                finally:watchdog.cancel()
                self.assertEqual(offset[0],jump)
                self.assertEqual(report['status'],'completed')
                self.assertEqual(report['findings'][0]['rule'],'meteor')
                self.assertEqual([f for e in events for f in e.get('new_findings',[])],report['findings'])
                self.assertEqual(report['time_budget_seconds'],limit)
                self.assertNotIn('stop_reason',report)

    def test_default_unlimited_scan_can_still_cancel_unresponsive_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            cancel=threading.Event();events=[];start=time.monotonic()
            def progress(data):events.append(data);cancel.set()
            report=run_scan(load_rules(RULES),[Path(tmp)],Path(tmp)/'state',False,cancel,progress,target=stalled_child)
            self.assertLess(time.monotonic()-start,3)
            self.assertEqual(report['status'],'cancelled')
            self.assertIsNone(report['time_budget_seconds'])
            self.assertTrue(report['partial_snapshot']);self.assertTrue(events)
            self.assertEqual(report['artifacts']['commands'][0]['command'],'echo fixture')

    def test_invalid_explicit_budget_is_rejected_before_starting_a_worker(self):
        for limit in (0,-1,float('nan'),float('inf')):
            with self.subTest(limit=limit),patch('atlasac.scanprocess.mp.get_context') as context:
                with self.assertRaises(ValueError):run_scan(load_rules(RULES),[],None,False,threading.Event(),lambda data:None,max_seconds=limit)
                context.assert_not_called()

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
            self.assertEqual(report['processed_candidates'],1);self.assertEqual(report['excluded_paths'],[str(skip)])

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
