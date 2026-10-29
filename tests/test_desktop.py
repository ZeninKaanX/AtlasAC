"""Exercise the native start/results flow with an actual scanner worker."""
import json,os,tempfile,time,unittest,zipfile
from pathlib import Path
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication,QLabel
from PySide6.QtTest import QTest
from atlasac.desktop import AtlasWindow,LOGO
from PySide6.QtGui import QImage

def pausing_scan_child(messages,cancel,rules,roots,data_dir,artifacts):
    from atlasac.scanprocess import scan_child
    class PausedMessages:
        def put(self,item):
            messages.put(item)
            if item[0]=='progress' and item[1].get('new_findings'):time.sleep(1)
    scan_child(PausedMessages(),cancel,rules,roots,data_dir,artifacts)

class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.mods=self.root/'outside-minecraft';self.mods.mkdir()
        self.window=AtlasWindow(history_dir=self.root/'reports',scan_roots=[self.mods],data_dir=self.root/'cache',collect_artifacts=False);self.window.show()
    def tearDown(self):
        if self.window.worker and self.window.worker.isRunning():self.window.worker.cancel.set();self.window.worker.wait(10000)
        self.window.close();self.app.processEvents();self.temp.cleanup()
    def test_native_flow_and_minimal_branding(self):
        with zipfile.ZipFile(self.mods/'renamed.dat','w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
        self.window.start_scan();deadline=time.monotonic()+10
        while self.window.worker.isRunning() and time.monotonic()<deadline:QTest.qWait(20)
        QTest.qWait(50)
        self.assertEqual(self.window.pages.count(),2)
        self.assertEqual(self.window.pages.currentIndex(),1)
        self.assertEqual(self.window.report['status'],'completed')
        self.assertEqual(self.window.model.rowCount(),1)
        self.assertEqual(self.window.model.rows[0]['rule'],'meteor')
        self.assertEqual(len(self.window.history.paths()),1)
        self.assertIn('E.V.',[w.text() for w in self.window.findChildren(QLabel)])
        self.assertTrue(QImage(str(LOGO)).hasAlphaChannel())
        self.assertEqual(QImage(str(LOGO)).pixelColor(0,0).alpha(),0)
        self.assertFalse(self.window.background.movie.currentPixmap().isNull())
    def test_empty_scope(self):
        self.window.scan_roots=[];self.window.start_scan();self.assertIsNone(self.window.report)
        self.assertIn('disk',self.window.status_label.text())
    def test_matching_file_is_visible_before_scan_finishes(self):
        from unittest.mock import patch
        from atlasac.scanprocess import run_scan
        with zipfile.ZipFile(self.mods/'client.dat','w') as z:z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client'}))
        def controlled(*args,**kwargs):return run_scan(*args,**kwargs,target=pausing_scan_child)
        with patch('atlasac.desktop.run_scan',side_effect=controlled):
            self.window.start_scan();deadline=time.monotonic()+10
            while not self.window.live_findings and self.window.worker.isRunning() and time.monotonic()<deadline:QTest.qWait(10)
            self.assertTrue(self.window.worker.isRunning())
            self.assertEqual(self.window.live_findings[0]['rule'],'meteor')
            self.assertEqual(self.window.report['findings'][0]['rule'],'meteor')
            self.assertEqual(self.window.live_model.keys[0],'path')
            self.assertIn('1 şüpheli eşleşme',self.window.status_label.text())
            self.window.live_filter.setCurrentIndex(1)
            self.assertEqual(self.window.live_model.rowCount(),1)
            self.assertTrue(self.window.progress_bar.timer.isActive())
            while self.window.worker.isRunning() and time.monotonic()<deadline:QTest.qWait(20)
            QTest.qWait(30)
            self.assertFalse(self.window.progress_bar.timer.isActive())
            self.assertEqual(len(self.window.report['findings']),1)
    def test_swimming_fish_frames_change(self):
        from atlasac.widgets import FishProgress
        strip=FishProgress();strip.resize(600,34);strip.show();QTest.qWait(40)
        before_image=strip.grab().toImage();before=bytes(before_image.bits())
        QTest.qWait(180)
        after_image=strip.grab().toImage();after=bytes(after_image.bits())
        self.assertNotEqual(before,after)
        strip.hide();self.assertFalse(strip.timer.isActive());strip.close()

    def test_animation_cache_and_minimize_preserve_result(self):
        from PySide6.QtGui import QMovie
        window=self.window;QTest.qWait(30)
        background=window.background
        background.set_suspended(True);background.grab()
        key=background._surface.cacheKey()
        background.grab();self.assertEqual(background._surface.cacheKey(),key)
        window.resize(window.width()+70,window.height()+30);QTest.qWait(20);background.grab()
        self.assertNotEqual(background._surface.cacheKey(),key)
        background.set_suspended(False)
        window.reveal.sound.setMuted(True)
        window.reveal.start({'status':'completed','findings':[]});QTest.qWait(20)
        self.assertEqual(background.movie.state(),QMovie.MovieState.Paused)
        self.assertEqual(window.reveal.timer.interval(),16)
        window.showMinimized();QTest.qWait(30)
        self.assertTrue(window.reveal.active)
        self.assertFalse(window.reveal.timer.isActive())
        self.assertFalse(window.progress_bar.timer.isActive())
        window.showNormal();QTest.qWait(30)
        self.assertTrue(window.reveal.active);self.assertTrue(window.reveal.timer.isActive())
        self.assertEqual(background.movie.state(),QMovie.MovieState.Paused)
        window.reveal.skip.click();QTest.qWait(20)
        self.assertFalse(window.reveal.active)
        self.assertEqual(background.movie.state(),QMovie.MovieState.Running)
        window.showMinimized();QTest.qWait(20)
        window.reveal.start({'status':'completed','findings':[]});QTest.qWait(20)
        self.assertTrue(window.reveal.active);self.assertFalse(window.reveal.timer.isActive())
        window.showNormal();QTest.qWait(20)
        self.assertTrue(window.reveal.active);self.assertTrue(window.reveal.timer.isActive())
