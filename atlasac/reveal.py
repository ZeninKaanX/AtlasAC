"""Native role-reveal animation driven by all 175 measured reference frames."""
import base64
import math
import json
import wave
from PySide6.QtCore import Qt,QTimer,QElapsedTimer,Signal,QRectF,QUrl,QByteArray,QBuffer,QIODevice,QPointF,QSize
from PySide6.QtGui import QPainter,QColor,QRadialGradient,QPixmap,QFont,QImageReader,QPainterPath
from PySide6.QtWidgets import QWidget,QPushButton
from PySide6.QtMultimedia import QSoundEffect
from .paths import ASSETS
from .widgets import FishProgress
from .pixels import clownfish,shark

GLYPHS={
'T':['11111','00100','00100','00100','00100','00100','00100'],
'e':['00000','00000','01110','10001','11111','10000','01111'],
'm':['00000','00000','11010','10101','10101','10101','10101'],
'i':['00100','00000','01100','00100','00100','00100','01110'],
'z':['00000','00000','11111','00010','00100','01000','11111'],
'Ş':['01111','10000','10000','01110','00001','00001','11110','00100','01000'],
'ü':['01010','00000','10001','10001','10001','10001','01111'],
'p':['00000','00000','11110','10001','11110','10000','10000'],
'h':['10000','10000','10110','11001','10001','10001','10001'],
'l':['01100','00100','00100','00100','00100','00100','01110'],
'a':['00000','00000','01110','00001','01111','10001','01111'],
'n':['00000','00000','10110','11001','10001','10001','10001'],
'd':['00001','00001','01101','10011','10001','10001','01111'],
'ı':['00000','00000','01100','00100','00100','00100','01110'],
}

def verdict_for(report):
    count=len(report.get('findings',[]))
    if count:return 'Şüpheli',f'{count} şüpheli eşleşme bulundu. Ayrıntıları incele.','#ed2639'
    if report.get('status')=='completed':return 'Temiz','Taranan aday dosyalarda bilinen hile eşleşmesi bulunmadı.','#55dbc6'
    detail='Süre sınırına ulaşıldı.' if report.get('stop_reason')=='time_budget' else 'Tarama kısmi kaldı veya durduruldu.'
    return 'Tamamlanmadı',detail+' Temiz sonucu verilemez.','#e4ad63'

def decode_icon(encoded):
    """Reject oversized or malformed embedded images before allocating pixels."""
    result=QPixmap()
    try:
        if not isinstance(encoded,str) or not encoded or len(encoded)>700000:return result
        raw=base64.b64decode(encoded,validate=True)
        if not raw.startswith(b'\x89PNG\r\n\x1a\n'):return result
        buffer=QBuffer();buffer.setData(QByteArray(raw));buffer.open(QIODevice.OpenModeFlag.ReadOnly)
        reader=QImageReader(buffer,b'png');size=reader.size()
        if size.width()<=0 or size.height()<=0 or max(size.width(),size.height())>2048:return result
        image=reader.read()
        if not image.isNull():result=QPixmap.fromImage(image)
    except (ValueError,TypeError):pass
    return result

class ResultReveal(QWidget):
    finished=Signal()
    activeChanged=Signal(bool)
    def __init__(self,parent,logo):
        super().__init__(parent);self.active=False;self._suspended=False
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self._static_frame=QPixmap();self._static_key=None
        self.reference=json.loads((ASSETS/'reveal-timing.json').read_text(encoding='utf-8'))
        self.peak=max(range(len(self.reference['frames'])),key=lambda j:(self.reference['frames'][j]['text'],self.reference['frames'][j]['glow']))
        self.clock=QElapsedTimer();self.timer=QTimer(self);self.timer.setInterval(16);self.timer.timeout.connect(self.tick)
        self.sound=QSoundEffect(self);self.sound.setSource(QUrl.fromLocalFile(str(ASSETS/'reveal.wav')));self.sound.setVolume(.7)
        with wave.open(str(ASSETS/'reveal.wav')) as audio:self.audio_seconds=audio.getnframes()/audio.getframerate()
        self.fish=clownfish(38)
        self.center_icon=QPixmap();self.center_name='';self.center_icons=[];self.clean=False;self.scaled_icons={}
        self.shark=shark(110)
        self.logo=QPixmap(str(logo));self.title='';self.detail='';self.color=QColor('#55dbc6')
        self.skip=QPushButton('Sonuçlar',self);self.skip.clicked.connect(self.finish)
        self.skip.setCursor(Qt.CursorShape.PointingHandCursor)
        self.skip.setStyleSheet('QPushButton { color: #bdd4df; background: #101820; border: 1px solid #37454f; border-radius: 7px; padding: 9px 18px; } QPushButton:hover {background:#253641;}')
        self.hide()
    def start(self,report):
        self.title,self.detail,color=verdict_for(report);self.color=QColor(color)
        self.scaled_icons.clear();self.clean=self.title=='Temiz';self.center_icon=QPixmap();self.center_name=''
        findings=report.get('findings',[]);self.center_icons=[];seen=set()
        for finding in findings:
            rule=str(finding.get('rule') or finding.get('name') or finding.get('path',''))
            if rule in seen:continue
            seen.add(rule);icon=QPixmap()
            if rule and all(c.isascii() and (c.isalnum() or c=='-') for c in rule):
                known=ASSETS/'client-icons'/(rule+'.png')
                if known.is_file():icon=QPixmap(str(known))
            if icon.isNull():icon=decode_icon(finding.get('icon_png_base64',''))
            self.center_icons.append((icon,str(finding.get('name',rule))[:70]))
        if self.center_icons:self.center_icon,self.center_name=self.center_icons[0]
        self.setAccessibleName('Tarama sonucu: '+self.title)
        self.setGeometry(self.parentWidget().rect());self.active=True;self.clock.start();self.show();self.raise_();self.skip.setFocus();self.sound.play();self.activeChanged.emit(True)
        if not self._suspended:self.timer.start()
        self.update()
    def tick(self):
        elapsed=self.clock.elapsed()/1000
        # The reveal holds its bright result and remains interactive until explicitly dismissed.
        if elapsed>=8 and self.sound.isPlaying():self.sound.stop()
        self.update()
    def finish(self):
        if not self.active:return
        self.active=False;self.timer.stop();self.sound.stop();self.hide();self.activeChanged.emit(False);self.finished.emit()
    def hideEvent(self,event):
        if hasattr(self,'timer'):self.timer.stop()
        # Spontaneous hide is window minimization, not a dismissal of the result.
        if event.spontaneous():
            super().hideEvent(event);return
        if hasattr(self,'sound'):self.sound.stop()
        was_active=self.active;self.active=False
        if was_active:self.activeChanged.emit(False)
        super().hideEvent(event)
    def showEvent(self,event):
        super().showEvent(event)
        if self.active and not self._suspended:self.timer.start()
    def set_suspended(self,value):
        self._suspended=bool(value)
        if self._suspended:self.timer.stop()
        elif self.active:self.timer.start()
    def resizeEvent(self,event):
        self._static_key=None;self.scaled_icons.clear()
        self.skip.adjustSize();self.skip.move(self.width()-self.skip.width()-26,self.height()-self.skip.height()-20);super().resizeEvent(event)
    def current_frame_index(self):
        return min(self.peak,int(self.clock.elapsed()*self.reference['fps_num']/self.reference['fps_den']/1000))
    def current_frame(self):return self.reference['frames'][self.current_frame_index()]
    def static_frame(self,f):
        dpr=self.devicePixelRatioF();w,h=self.width(),self.height()
        key=(self.current_frame_index(),w,h,dpr,self.title,self.detail,self.color.rgba())
        if key==self._static_key:return self._static_frame
        frame=QPixmap(QSize(max(1,round(w*dpr)),max(1,round(h*dpr))));frame.setDevicePixelRatio(dpr);frame.fill(QColor('black'))
        p=QPainter(frame);p.setRenderHint(QPainter.RenderHint.Antialiasing);bounds=f['bounds']
        if bounds and f['glow']>0:
            left,top,right,bottom=bounds;cx=(left+right)*w/2;cy=(top+bottom)*h/2
            rx=max(1,(right-left)*w/2);ry=max(1,(bottom-top)*h/2)
            p.save();p.translate(cx,cy);p.scale(rx,ry)
            glow=QRadialGradient(0,0,1);color=QColor(self.color);color.setAlphaF(min(.75,f['glow']*.72))
            glow.setColorAt(0,color);edge=QColor(self.color);edge.setAlpha(0);glow.setColorAt(1,edge)
            p.setPen(Qt.PenStyle.NoPen);p.setBrush(glow);p.drawEllipse(QRectF(-1,-1,2,2));p.restore()
        p.setRenderHint(QPainter.RenderHint.Antialiasing,False)
        p.setOpacity(f['text']);p.setPen(Qt.PenStyle.NoPen);p.setBrush(self.color)
        cells=max(1,len(self.title)*6-1);scale=min(w/70,h/42,w*.86/cells)
        x=(w-cells*scale)/2;y=f['y']*h
        for char in self.title:
            for row,line in enumerate(GLYPHS.get(char,GLYPHS['i'])):
                for col,value in enumerate(line):
                    if value=='1':p.drawRect(QRectF(x+col*scale,y+row*scale,scale,scale))
            x+=6*scale
        p.setRenderHint(QPainter.RenderHint.Antialiasing,True)
        p.setPen(QColor('#c8dbe4'));p.setFont(QFont('Poppins',max(10,int(h/64))))
        p.drawText(QRectF(w*.1,h*.79,w*.8,h*.08),Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignTop|Qt.TextFlag.TextWordWrap,self.detail)
        p.end();self._static_frame=frame;self._static_key=key;return frame
    def paintEvent(self,event):
        p=QPainter(self)
        if not self.active:p.fillRect(self.rect(),QColor('black'));p.end();return
        f=self.current_frame();w,h=self.width(),self.height()
        p.drawPixmap(0,0,self.static_frame(f));p.setOpacity(f['text'])
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.clean:
            t=self.clock.elapsed()/1000
            # The shark has gone; the surviving school swims together in the centre.
            for i in range(5):
                x=w*.5+(i-2)*self.fish.width()*.7+math.sin(t*1.4)*25-self.fish.width()/2
                y=h*.54+math.sin(t*2+i*1.3)*14+(i%2)*22-self.fish.height()/2
                FishProgress.swim(p,self.fish,x,y,t*8+i,3)
            p.setPen(QColor('#8be2e4'));p.setBrush(Qt.BrushStyle.NoBrush)
            for i in range(7):
                p.drawEllipse(QPointF(w*.35+i*w*.05,h*.66-((t*32+i*23)%(h*.27))),2,2)
        else:
            entries=self.center_icons or [(QPixmap(),'')];count=len(entries)
            span=w*.76;cell=span/count;size=int(min(h*.25,cell*.8));cy=h*.53;t=(self.clock.elapsed()/1000)%6
            shark_x=-self.shark.width()+(t-.6)/2.6*(w+self.shark.width()*2)
            head=shark_x+self.shark.width()*.9
            for i,(icon,name) in enumerate(entries):
                x=w*.12+cell*(i+.5);source=icon if not icon.isNull() else self.logo
                key=(source.cacheKey(),size)
                if key not in self.scaled_icons:self.scaled_icons[key]=source.scaled(max(1,size),max(1,size),Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation)
                logo=self.scaled_icons[key]
                biting=not icon.isNull() and abs(head-x)<self.shark.width()*.13
                p.save();p.translate(x,cy)
                if biting:p.rotate(math.sin(t*65)*9);p.translate(math.sin(t*85)*5,math.cos(t*75)*3)
                if biting:
                    outline=QPainterPath();outline.addRect(QRectF(-size,-size,size*2,size*2))
                    bite=QPainterPath();bite.addEllipse(QPointF(-logo.width()*.39,0),max(3,size*.2),max(3,size*.2))
                    p.setClipPath(outline.subtracted(bite))
                p.drawPixmap(-logo.width()//2,-logo.height()//2,logo)
                p.restore()
                if name:
                    p.setPen(QColor('#d4dfe5'));p.setFont(QFont('Poppins',max(7,min(14,int(cell/12)))))
                    p.drawText(QRectF(x-cell/2,cy+size/2+8,cell,h*.06),Qt.AlignmentFlag.AlignCenter,name)
            if any(not icon.isNull() for icon,name in self.center_icons) and .4<t<3.65:
                dive=0
                for i,(icon,name) in enumerate(entries):
                    if icon.isNull():
                        x=w*.12+cell*(i+.5)
                        dive=max(dive,min(h*.23,size+self.shark.height()*.6)*math.exp(-((head-x)/(size*.5+self.shark.width()*.35))**2))
                FishProgress.swim_shark(p,self.shark,shark_x,cy-self.shark.height()/2+dive,t*9,5)
        p.end()
