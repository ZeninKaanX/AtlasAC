import os,time,unittest
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication,QWidget
from PySide6.QtTest import QTest
from atlasac.reveal import ResultReveal,verdict_for,decode_icon
from atlasac.desktop import LOGO

class RevealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.app=QApplication.instance() or QApplication([])
    def test_verdict_does_not_call_partial_or_timed_out_scan_clean(self):
        self.assertEqual(verdict_for({'status':'completed','findings':[]})[0],'Temiz')
        self.assertEqual(verdict_for({'status':'partial','findings':[],'stop_reason':'time_budget'})[0],'Tamamlanmadı')
        self.assertEqual(verdict_for({'status':'cancelled','findings':[]})[0],'Tamamlanmadı')
        self.assertEqual(verdict_for({'status':'partial','findings':[{'rule':'meteor'}]})[0],'Şüpheli')
    def test_center_uses_embedded_icon_fallback_and_clean_school(self):
        import base64
        parent=QWidget();overlay=ResultReveal(parent,LOGO);overlay.sound.setMuted(True)
        try:
            icon='iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGP4DwQACfsD/fteaysAAAAASUVORK5CYII='
            overlay.start({'status':'completed','findings':[{'name':'Test client','icon_png_base64':icon}]})
            self.assertFalse(overlay.center_icon.isNull());self.assertFalse(overlay.clean)
            overlay.finish()
            overlay.start({'status':'completed','findings':[{'name':'Without icon'}]})
            self.assertTrue(overlay.center_icon.isNull());self.assertEqual(overlay.center_name,'Without icon')
            overlay.finish()
            overlay.start({'status':'completed','findings':[{'rule':'one','name':'One'},{'rule':'two','name':'Two'},{'rule':'one','name':'One again'}]})
            self.assertEqual(len(overlay.center_icons),2)
            overlay.finish()
            overlay.start({'status':'completed','findings':[]})
            self.assertTrue(overlay.clean);self.assertFalse(overlay.fish.isNull())
            self.assertTrue(decode_icon('broken').isNull());overlay.finish()
        finally:parent.close()
    def test_shark_jaw_moves_without_moving_body_and_fish_are_smaller(self):
        import math
        from PySide6.QtGui import QPixmap,QPainter,QColor
        from atlasac.widgets import FishProgress
        from atlasac.pixels import shark
        sprite=shark(100);frames=[]
        for phase in (math.pi/1.1,3*math.pi/1.1):
            frame=QPixmap(350,150);frame.fill(QColor('#123d53'));p=QPainter(frame)
            FishProgress.swim_shark(p,sprite,0,0,phase,0);p.end();frames.append(frame.toImage())
        self.assertEqual(frames[0].copy(0,0,int(sprite.width()*.78),100),frames[1].copy(0,0,int(sprite.width()*.78),100))
        self.assertNotEqual(frames[0],frames[1])
        strip=FishProgress()
        self.assertLess(strip.fish.width(),strip.shark.width()/2)
        self.assertLess(strip.fish.height(),strip.shark.height()/2)
        strip.close()
    def test_reference_sound_ends_but_result_waits_for_click(self):
        parent=QWidget();parent.resize(960,600);parent.show();overlay=ResultReveal(parent,LOGO);overlay.sound.setMuted(True);done=[];overlay.finished.connect(lambda:done.append(True))
        try:
            self.assertEqual(overlay.reference['frame_count'],175)
            overlay.start({'status':'completed','findings':[]});start=time.monotonic()
            QTest.qWait(6250)
            self.assertTrue(overlay.active);self.assertEqual(len(done),0)
            self.assertFalse(overlay.sound.isPlaying())
            self.assertGreater(overlay.current_frame()['text'],.9)
            overlay.skip.click();self.assertFalse(overlay.active);self.assertEqual(len(done),1)
            overlay.start({'status':'completed','findings':[{'rule':'meteor'}]})
            self.assertEqual(overlay.title,'Şüpheli');overlay.finish();self.assertEqual(len(done),2)
            self.assertFalse(overlay.timer.isActive());self.assertFalse(overlay.sound.isPlaying())
            self.assertGreater(overlay.audio_seconds,5.8)
        finally:parent.close()
