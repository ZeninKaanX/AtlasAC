import tempfile,threading,time,unittest
from pathlib import Path
from atlasac.scanplan import ScanPlan
from atlasac.scanprogress import ScanProgress
from atlasac.integrity import validate_file_progress
from atlasac.filepolicy import candidate_name


class ProgressTests(unittest.TestCase):
    def test_unknown_inventory_has_no_percentage_and_eta_needs_measured_throughput(self):
        progress=ScanProgress()
        self.assertIsNone(progress.update(1,10,False,0)['progress_percent'])
        self.assertIsNone(progress.update(2,100,False,1)['eta_seconds'])
        self.assertIsNone(progress.update(20,100,True,1)['eta_seconds'])
        state=progress.update(30,100,True,3)
        self.assertEqual(state['progress_percent'],30)
        self.assertIsNotNone(state['eta_seconds'])
        self.assertGreater(state['eta_seconds'],0)
        self.assertIsNone(progress.update(30,100,True,15)['eta_seconds'])
        final=progress.update(100,100,True,16)
        self.assertEqual(final['progress_percent'],100);self.assertEqual(final['eta_seconds'],0)

    def test_progress_cannot_invent_a_percentage_or_change_a_finished_inventory(self):
        state=dict(files_seen=20,discovered_candidates=10,directories_seen=1,processed_candidates=5,
                   discovery_complete=True,total_candidates=10,progress_percent=50.,eta_seconds=2)
        validate_file_progress(state,{})
        for changes in ({'progress_percent':99.},{'processed_candidates':11},
                        {'discovery_complete':False},{'total_candidates':11,'discovered_candidates':11}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):validate_file_progress(dict(state,**changes),state)
        with self.assertRaises(ValueError):validate_file_progress(dict(state,discovery_complete=False),{})

    def test_spooled_discovery_keeps_every_candidate_and_prioritises_archives(self):
        self.assertTrue(candidate_name('...jar',True));self.assertTrue(candidate_name('trailing.'))
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);disk=base/'disk';disk.mkdir();state=base/'state';state.mkdir()
            for i in range(1100):(disk/f'ordinary-{i}.dat').write_bytes(b'fixture')
            for i in range(5):(disk/f'late-{i}.JAR').write_bytes(b'fixture')
            for i in range(5):(disk/f'image-{i}.png').write_bytes(b'image')
            unusual=disk/'space ü file.dat';unusual.write_bytes(b'fixture')
            plan=ScanPlan([disk],{},[state],threading.Event(),state)
            try:
                plan.thread.join(timeout=5);self.assertFalse(plan.thread.is_alive())
                first=plan.take(5);self.assertTrue(all(r['path'].endswith('.JAR') for r in first))
                rows=first;deadline=time.monotonic()+5
                while not plan.exhausted() and time.monotonic()<deadline:rows.extend(plan.take(64))
                self.assertTrue(plan.exhausted())
                files=[r for r in rows if r['kind']=='file']
                self.assertEqual(len(files),1106);self.assertEqual(len({r['path'] for r in files}),1106)
                self.assertIn(str(unusual),[r['path'] for r in files])
                snapshot=plan.snapshot();self.assertEqual(snapshot['ignored_files'],5)
                self.assertEqual(snapshot['discovered_candidates'],1106);self.assertTrue(snapshot['discovery_complete'])
            finally:plan.close()
            self.assertTrue(plan.stream.closed)
