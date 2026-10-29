"""Native elapsed-time swimming with transparent animal artwork."""
import math
from PySide6.QtCore import Qt,QTimer,QElapsedTimer,QSize,QPointF,QRectF
from PySide6.QtGui import QPainter,QPainterPath,QColor,QLinearGradient,QPixmap
from PySide6.QtWidgets import QWidget
from .pixels import clownfish,shark

class FishProgress(QWidget):
    """Indeterminate current; the school leads a shark from left to right."""
    def __init__(self,parent=None):
        super().__init__(parent);self.setFixedHeight(34)
        self.setAccessibleName('Tarama sürüyor — köpek balığının önünde sağa yüzen balıklar')
        self.shark=shark(29)
        self.fish=clownfish(12)
        self._suspended=False;self.clock=QElapsedTimer();self.clock.start();self.timer=QTimer(self)
        self.timer.setTimerType(Qt.TimerType.PreciseTimer);self.timer.setInterval(16);self.timer.timeout.connect(self.update)
    def sizeHint(self):return QSize(500,34)
    def set_suspended(self,value):
        self._suspended=bool(value)
        if self._suspended:self.timer.stop()
        elif self.isVisible():self.timer.start()
    def showEvent(self,event):
        if not self._suspended:self.timer.start()
        super().showEvent(event)
    def hideEvent(self,event):self.timer.stop();super().hideEvent(event)
    @staticmethod
    def swim(p,sprite,x,y,phase,amplitude):
        # Tail bends more than the head. Cached sprites avoid resampling large art.
        width,height=sprite.width(),sprite.height()
        for i in range(12):
            left=i*width/12;right=(i+1)*width/12
            bend=amplitude*(1-i/12)**2*math.sin(phase-i*.4)
            p.drawPixmap(QRectF(x+left,y+bend,right-left+.35,height),sprite,QRectF(left,0,right-left+.35,height))
    @staticmethod
    def swim_shark(p,sprite,x,y,phase,amplitude):
        w,h=sprite.width(),sprite.height()
        jaw=QPainterPath()
        jaw.moveTo(w*.813,h*.694)
        for px,py in ((.84,.68),(.865,.73),(.88,.76),(.89,.70),(.905,.77),(.92,.79),(.934,.70),(.95,.77),(.963,.70),(.98,.76),(1,.76),(1,1),(.81,1)):
            jaw.lineTo(w*px,h*py)
        jaw.closeSubpath()
        body=QPainterPath();body.addRect(QRectF(-4,-4,w+8,h+8))
        p.save();p.translate(x,y);p.setClipPath(body.subtracted(jaw),Qt.ClipOperation.IntersectClip)
        FishProgress.swim(p,sprite,0,0,phase,amplitude);p.restore()
        p.save();p.translate(x+w*.813,y+h*.72)
        # The lower jaw pivots at the hinge; the skull never stretches or slides.
        p.rotate(-9*(.5+.5*math.sin(phase*.55)))
        p.translate(-w*.813,-h*.72);p.setClipPath(jaw,Qt.ClipOperation.IntersectClip)
        p.drawPixmap(0,0,sprite);p.restore()
    def paintEvent(self,event):
        p=QPainter(self);p.setRenderHint(QPainter.RenderHint.Antialiasing);p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform,False)
        w,h=self.width(),self.height();t=self.clock.elapsed()/1000
        clip=QPainterPath();clip.addRoundedRect(0,0,w,h,10,10);p.setClipPath(clip)
        water=QLinearGradient(0,0,0,h);water.setColorAt(0,QColor(5,47,69,215));water.setColorAt(1,QColor(13,115,147,200));p.fillRect(self.rect(),water)
        wave=QPainterPath();wave.moveTo(0,h)
        for x in range(0,w+9,8):wave.lineTo(x,6+2*math.sin(x/43-t*2))
        wave.lineTo(w,h);wave.closeSubpath();p.fillPath(wave,QColor(44,173,206,35))
        cycle=w+230;origin=(t*105+110)%cycle-110
        for base in (origin,origin-cycle):
            if base>w or base+270<0:continue
            self.swim_shark(p,self.shark,base,h*.5-self.shark.height()/2+math.sin(t*2)*.6,t*8,1.1)
            for i in range(3):
                x=base+118+i*48+3*math.sin(t*2+i)
                y=h*.5-self.fish.height()/2+math.sin(t*3+i*2)*3
                self.swim(p,self.fish,x,y,t*11+i,1)
        p.setPen(QColor(169,237,255,85));p.setBrush(Qt.BrushStyle.NoBrush)
        for i in range(10):p.drawEllipse(QPointF((i*w/10+t*14)%max(w,1),h-((t*10+i*11)%(h+6))),1.4,1.4)
        p.end()
