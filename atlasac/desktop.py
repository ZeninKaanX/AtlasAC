"""Native, two-page Qt desktop scanner. All reports and indices stay on the device."""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
import sys
import threading
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QAbstractTableModel, QModelIndex, QEvent, QSize
from PySide6.QtGui import QColor, QFont, QFontDatabase, QIcon, QMovie, QPainter, QPixmap
from PySide6.QtWidgets import (QApplication,QMainWindow,QWidget,QHBoxLayout,QVBoxLayout,QLabel,
    QPushButton,QFileDialog,QStackedWidget,QProgressBar,QHeaderView,QPlainTextEdit,
    QButtonGroup,QComboBox,QLineEdit,QTableView,QDialog,QCheckBox,QDialogButtonBox,QMessageBox)
from . import __version__
from .engine import load_rules, now
from .paths import ASSETS, RULES
from .reports import ReportHistory
from .systemscan import system_scan, computer_roots
from .index import search_files,purge_index,maintain_index
from .audit import AuditTrail
from .privacy import notice_text,NOTICE_VERSION,minimize_report
from .securestore import write_json
from .widgets import FishProgress
from .scanprocess import run_scan
from .reveal import ResultReveal

LOGO=ASSETS/'atlasac-mobile-transparent.png'

def label(text,style=''):
    widget=QLabel(text);widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setStyleSheet(style);return widget

def button(text,callback,primary=False):
    widget=QPushButton(text);widget.setProperty('primary',primary)
    widget.setCursor(Qt.CursorShape.PointingHandCursor);widget.clicked.connect(callback);return widget

class ScanNotice(QDialog):
    def __init__(self,parent=None):
        super().__init__(parent);self.setWindowTitle('AtlasAC · Tarama öncesi bilgilendirme');self.resize(760,640)
        self.setStyleSheet(STYLE)
        layout=QVBoxLayout(self);text=QPlainTextEdit();text.setReadOnly(True);text.setPlainText(notice_text());layout.addWidget(text)
        self.permission=QCheckBox('Bu cihazı incelemeye yetkiliyim ve belirtilen kapsamda yerel taramayı başlatmak istiyorum.')
        self.permission.setChecked(False);layout.addWidget(self.permission)
        hint=label('Bu seçim teknik tarama iznidir; kuruluşun hukuki işleme şartını belirlemez.');hint.setWordWrap(True);layout.addWidget(hint)
        buttons=QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.start=buttons.addButton('Taramayı başlat',QDialogButtonBox.ButtonRole.AcceptRole);self.start.setEnabled(False)
        buttons.button(QDialogButtonBox.StandardButton.Cancel).setText('Vazgeç')
        self.permission.toggled.connect(self.start.setEnabled);buttons.accepted.connect(self.accept);buttons.rejected.connect(self.reject);layout.addWidget(buttons)

class OceanBackground(QWidget):
    def __init__(self):
        super().__init__()
        self.setAttribute(Qt.WidgetAttribute.WA_OpaquePaintEvent)
        self._surface=QPixmap();self._surface_key=None;self._suspended=False;self._window_visible=True
        self.movie=QMovie(str(ASSETS/'atlasoyuncu-background.gif'))
        # Twenty 800x450 source frames: bounded ~29 MiB, no recurring GIF decode.
        self.movie.setCacheMode(QMovie.CacheMode.CacheAll)
        self.movie.frameChanged.connect(self.update);self.movie.jumpToFrame(0)
    def sync_animation(self):
        running=self.isVisible() and self._window_visible and not self._suspended
        if running:
            if self.movie.state()==QMovie.MovieState.NotRunning:self.movie.start()
            else:self.movie.setPaused(False)
        else:self.movie.setPaused(True)
    def set_suspended(self,value):self._suspended=bool(value);self.sync_animation()
    def set_window_visible(self,value):self._window_visible=bool(value);self.sync_animation()
    def showEvent(self,event):super().showEvent(event);self.sync_animation()
    def hideEvent(self,event):self.movie.setPaused(True);super().hideEvent(event)
    def paintEvent(self,event):
        dpr=self.devicePixelRatioF();key=(self.movie.currentFrameNumber(),self.width(),self.height(),dpr)
        if key!=self._surface_key:
            size=QSize(max(1,round(self.width()*dpr)),max(1,round(self.height()*dpr)))
            surface=QPixmap(size);surface.setDevicePixelRatio(dpr);surface.fill(QColor('#04101d'))
            p=QPainter(surface);frame=self.movie.currentPixmap()
            if not frame.isNull():
                frame=frame.scaled(size,Qt.AspectRatioMode.KeepAspectRatioByExpanding,Qt.TransformationMode.SmoothTransformation);frame.setDevicePixelRatio(dpr)
                p.drawPixmap(round((self.width()-frame.width()/dpr)/2),round((self.height()-frame.height()/dpr)/2),frame)
            p.fillRect(self.rect(),QColor(4,15,29,95));p.end()
            self._surface=surface;self._surface_key=key
        painter=QPainter(self);painter.drawPixmap(0,0,self._surface)

class ScanWorker(QThread):
    progress=Signal(object)
    ready=Signal(object)
    def __init__(self,roots,rules,data_dir,artifacts=True,max_seconds=600):
        super().__init__();self.roots=roots;self.rules=rules;self.data_dir=data_dir
        self.artifacts=artifacts;self.max_seconds=max_seconds;self.cancel=threading.Event()
    def run(self):
        try:
            report=run_scan(self.rules,self.roots,self.data_dir,self.artifacts,self.cancel,self.progress.emit,self.max_seconds)
        except Exception as exc:
            report={'started_at':now(),'roots':list(map(str,self.roots)),'status':'partial','files':[],
                    'findings':[],'issues':[{'reason':str(exc)}],'components':[],'artifacts':{}}
        self.ready.emit(report)

class Rows(QAbstractTableModel):
    def __init__(self):
        super().__init__();self.rows=[];self.keys=[]
    def set_rows(self,rows):
        self.beginResetModel();self.rows=rows
        keys=list(dict.fromkeys(k for row in rows[:100] for k in row))
        keys=[k for k in keys if k!='icon_png_base64' and any(row.get(k) not in (None,'',[],{}) for row in rows[:100])]
        first=('path','status','name','rule','method','format','evidence','note')
        self.keys=[k for k in first if k in keys]+[k for k in keys if k not in first]
        self.endResetModel()
    def rowCount(self,parent=QModelIndex()):return 0 if parent.isValid() else len(self.rows)
    def columnCount(self,parent=QModelIndex()):return 0 if parent.isValid() else len(self.keys)
    def data(self,index,role=Qt.ItemDataRole.DisplayRole):
        if index.isValid() and role in (Qt.ItemDataRole.DisplayRole,Qt.ItemDataRole.ToolTipRole):
            value=self.rows[index.row()].get(self.keys[index.column()],'')
            return json.dumps(value,ensure_ascii=False) if isinstance(value,(list,dict)) else str(value if value is not None else '')
    def headerData(self,section,orientation,role=Qt.ItemDataRole.DisplayRole):
        if role==Qt.ItemDataRole.DisplayRole:
            return HEADERS.get(self.keys[section],self.keys[section]) if orientation==Qt.Orientation.Horizontal else str(section+1)

HEADERS={'evidence_level':'Delil düzeyi','observed_state':'Gözlem','usage_proven':'Kullanım kanıtlandı','session_link':'Oturum bağlantısı','active_features':'Aktif özellikler','method_id':'Rehber yöntemi','capability':'Yetenek','collection_status':'Toplama durumu','sources_present':'Mevcut kaynaklar','gap':'Kapsam dışı','platform':'Platform','classification':'Sınıflandırma','record_id':'Kayıt no','event_id':'Olay no','kind':'Kayıt türü','truncated':'Metin sınırı','fragment':'Parça','fragment_total':'Parça sayısı','provider':'Sağlayıcı','path':'Dosya','rule':'Kural','name':'Ad','category':'Tür','method':'Yöntem','evidence':'İz','note':'Açıklama','reason':'Açıklama','size':'Boyut','format':'Biçim','status':'Durum','records':'Kayıt','detail':'Ayrıntı','process':'İşlem','started_at':'Başlama zamanı','command':'Komut','source':'Kaynak','url':'Adres','title':'Başlık','timestamp':'Zaman','visited_at':'Ziyaret zamanı'}

STYLE='''
QWidget { color: #eff9ff; font-size: 14px; }
QPushButton { background: rgba(10,35,56,190); border: 1px solid #4a8bac; border-radius: 9px; padding: 10px 22px; }
QPushButton:hover, QPushButton:checked { background: #176a93; border-color: #90e1ff; }
QPushButton:disabled { color: #8096aa; border-color: #486071; }
QPushButton[primary="true"] { background: #1199cf; font-size: 20px; padding: 16px 48px; font-weight: 600; }
QTableView,QPlainTextEdit { background: rgba(5,20,35,205); alternate-background-color: #143149; border: 1px solid #397493; border-radius: 8px; selection-background-color: #216187; }
QHeaderView::section { background: #14384e; color: #ceefff; border: 0; padding: 9px; }
QLineEdit,QComboBox { background: rgba(7,27,43,210); border: 1px solid #4787a4; border-radius: 7px; padding: 9px; }
QComboBox QAbstractItemView { background: #102e44; selection-background-color: #216187; }
QProgressBar { background: rgba(8,28,43,150); border: 0; border-radius: 4px; height: 7px; }
QProgressBar::chunk { background: #82dcff; border-radius: 4px; }
QDialog { background: #0b2335; }
'''

class AtlasWindow(QMainWindow):
    def __init__(self,rules_path=RULES,history_dir=None,scan_roots=None,data_dir=None,collect_artifacts=True):
        super().__init__();self.rules=load_rules(rules_path);self.history=ReportHistory(history_dir)
        self.scan_roots=scan_roots;self.data_dir=data_dir;self.collect_artifacts=collect_artifacts
        self.audit=AuditTrail(data_dir);maintain_index(self.audit.base)
        self.report=None;self.worker=None;self.closing=False;self.live_files=[];self.live_findings=[]
        self.setWindowTitle('AtlasAC • AtlasOyuncu • '+__version__);self.setWindowIcon(QIcon(str(LOGO)))
        self.resize(1180,780);self.setMinimumSize(840,600)
        self.background=OceanBackground();self.setCentralWidget(self.background)
        outer=QVBoxLayout(self.background);outer.setContentsMargins(34,24,34,16);outer.setSpacing(20)
        header=QHBoxLayout();logo=QLabel();logo.setPixmap(QPixmap(str(LOGO)).scaled(54,54,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
        header.addWidget(logo);header.addWidget(label('AtlasAC','font-size: 25px; font-weight: 600;'))
        header.addStretch();self.pages=QStackedWidget();self.nav=QButtonGroup(self)
        for i,name in enumerate(('Tarama','Sonuçlar')):
            item=button(name,lambda checked=False,n=i:self.navigate(n));item.setCheckable(True)
            self.nav.addButton(item,i);header.addWidget(item)
        outer.addLayout(header);outer.addWidget(self.pages,1)
        footer=QHBoxLayout();footer.addStretch();footer.addWidget(label('E.V.','color: #c9ecff; font-size: 12px; letter-spacing: 2px;'))
        outer.addLayout(footer);self.build_scan();self.build_results();self.navigate(0);self.setStyleSheet(STYLE)
        self.reveal=ResultReveal(self.background,LOGO);self.reveal.activeChanged.connect(self.background.set_suspended);self.reveal.finished.connect(lambda:self.navigate(1))
    def navigate(self,index):
        self.pages.setCurrentIndex(index);self.nav.button(index).setChecked(True)
    def build_scan(self):
        page=QWidget();layout=QVBoxLayout(page);layout.setContentsMargins(70,10,70,35);layout.addStretch(2)
        logo=QLabel();logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setPixmap(QPixmap(str(LOGO)).scaled(170,170,Qt.AspectRatioMode.KeepAspectRatio,Qt.TransformationMode.SmoothTransformation))
        layout.addWidget(logo);scope=label('JAR/ZIP ve aday dosyalar · En fazla 10 dakika','color: #d6f1ff; font-size: 16px;')
        scope.setWordWrap(True);scope.setAlignment(Qt.AlignmentFlag.AlignCenter);layout.addWidget(scope);layout.addSpacing(22)
        controls=QHBoxLayout();controls.addStretch()
        self.start_button=button('Taramayı başlat',self.start_scan,True);controls.addWidget(self.start_button)
        self.stop_button=button('Durdur',self.cancel_scan);self.stop_button.hide();controls.addWidget(self.stop_button)
        controls.addStretch();layout.addLayout(controls);layout.addSpacing(18)
        self.status_label=label('Hazır');self.status_label.setWordWrap(True);self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter);layout.addWidget(self.status_label)
        self.progress_bar=FishProgress();self.progress_bar.hide();layout.addWidget(self.progress_bar)
        self.path_label=label('','color: #bcdeef; font-size: 11px;');self.path_label.setMaximumHeight(36);self.path_label.setWordWrap(True)
        layout.addWidget(self.path_label)
        self.live_filter=QComboBox();self.live_filter.addItem('Canlı dosyalar — son 160 kayıt','files');self.live_filter.addItem('Dosya eşleşmeleri','findings');self.live_filter.addItem('İnceleme sinyalleri','review_signals')
        self.live_filter.currentIndexChanged.connect(self.refresh_live)
        layout.addWidget(self.live_filter);self.live_filter.hide()
        self.live_model=Rows();self.live_table=QTableView();self.live_table.setModel(self.live_model)
        self.live_table.setMaximumHeight(160);self.live_table.setMinimumHeight(100);self.live_table.setWordWrap(False)
        self.live_table.verticalHeader().hide();self.live_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.live_table);self.live_table.hide()
        layout.addStretch(1);self.pages.addWidget(page)
    def build_results(self):
        page=QWidget();layout=QVBoxLayout(page);layout.setContentsMargins(0,0,0,4)
        self.summary=label('Henüz tarama yapılmadı.','font-size: 21px; font-weight: 600;');self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        controls=QHBoxLayout();self.category=QComboBox()
        self.category.addItem('Sonuçlar','findings');self.category.addItem('Dosya indeksi','index')
        self.category.addItem('Erişim ve kapsam','coverage');self.category.currentIndexChanged.connect(self.refresh_results)
        controls.addWidget(self.category);self.search=QLineEdit();self.search.setPlaceholderText('Sonuçlarda ara…');controls.addWidget(self.search,1)
        self.search_timer=QTimer(self);self.search_timer.setSingleShot(True);self.search_timer.timeout.connect(self.refresh_results)
        self.search.textChanged.connect(lambda _:self.search_timer.start(250))
        controls.addWidget(button('JSON kaydet',self.export_report));controls.addWidget(button('Yerel verileri sil',self.clear_local_data));layout.addLayout(controls)
        self.model=Rows();self.result_table=QTableView();self.result_table.setModel(self.model)
        self.result_table.setAlternatingRowColors(True);self.result_table.setWordWrap(False)
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.result_table.horizontalHeader().setStretchLastSection(True);self.result_table.doubleClicked.connect(self.open_details)
        layout.addWidget(self.result_table,1);self.result_note=label('','color: #c9e4f3; font-size: 12px;');self.result_note.setWordWrap(True)
        layout.addWidget(self.result_note);self.pages.addWidget(page)
    def confirm_scan(self):
        return ScanNotice(self).exec()==QDialog.DialogCode.Accepted
    def start_scan(self):
        if self.worker and self.worker.isRunning():return
        roots=computer_roots() if self.scan_roots is None else self.scan_roots
        if not roots:self.status_label.setText('Taranabilecek yerel disk bulunamadı.');return
        if not self.confirm_scan():return
        try:self.history.maintain();self.audit.record('scan-start')
        except OSError as exc:self.status_label.setText('Özel kayıt alanı hazırlanamadı: '+str(exc));return
        self.report={'started_at':now(),'status':'running','roots':list(map(str,roots)),'findings':[],'files':[],'issues':[],'artifacts':{},'components':[]}
        self.live_files=[];self.live_findings=[];self.live_model.set_rows([]);self.live_filter.setCurrentIndex(0)
        self.live_filter.show();self.live_table.show()
        self.summary.setText('Tarama sürüyor…');self.model.set_rows([])
        self.start_button.setEnabled(False);self.stop_button.show();self.stop_button.setEnabled(True)
        self.progress_bar.show();self.status_label.setText('Tarama başlatılıyor…')
        self.worker=ScanWorker(roots,self.rules,self.data_dir,self.collect_artifacts)
        self.worker.progress.connect(self.on_progress);self.worker.ready.connect(self.display_report)
        self.worker.finished.connect(self.scan_finished);self.worker.start()
    def on_progress(self,data):
        cancelling=self.worker and self.worker.cancel.is_set()
        phase='Durduruluyor…' if cancelling else data['phase']
        self.status_label.setText(f"{phase} · {data['indexed']:,} aday dosya · {data.get('ignored_files',0):,} normal dosya atlandı · {data['matches']} şüpheli eşleşme")
        self.path_label.setText(data['path'][-180:])
        self.live_files=(self.live_files+data.get('recent_files',[]))[-160:]
        self.live_findings.extend(data.get('new_findings',[]))
        if self.report and self.report.get('status')=='running':
            self.report.update(indexed_files=data['indexed'],content_files=data.get('content_files',0),excluded_paths=data.get('excluded_paths',[]),exclusion_reasons=data.get('exclusion_reasons',{}),
                               index_path=data.get('index_path'),scan_id=data.get('scan_id'),findings=list(self.live_findings))
            self.report['artifacts'].update(data.get('artifact_snapshot',{}))
            for key,rows in data.get('artifact_delta',{}).items():self.report['artifacts'].setdefault(key,[]).extend(rows)
            self.report['components']=data.get('components',self.report.get('components',[]))
            for key,value in self.report['artifacts'].items():
                if isinstance(value,list) and self.category.findData(key)<0:self.category.addItem(TITLES.get(key,key),key)
            self.summary.setText(f"Tarama sürüyor · {data['indexed']:,} dosya · {data['matches']} şüpheli eşleşme")
            if self.pages.currentIndex()==1:self.refresh_results()
        self.refresh_live()
    def refresh_live(self):
        if not hasattr(self,'live_model'):return
        key=self.live_filter.currentData()
        rows=self.live_findings if key=='findings' else (self.report or {}).get('artifacts',{}).get('review_signals',[]) if key=='review_signals' else self.live_files
        self.live_model.set_rows(list(reversed(rows)))
        if self.live_model.columnCount():self.live_table.setColumnWidth(0,520)
    def cancel_scan(self):
        if self.worker:self.worker.cancel.set();self.stop_button.setEnabled(False);self.status_label.setText('Durduruluyor…')
    def scan_finished(self):
        self.start_button.setEnabled(True);self.stop_button.hide();self.progress_bar.hide()
        if self.closing:self.close()
    def display_report(self,report):
        report=minimize_report(report);report['privacy_notice_version']=NOTICE_VERSION
        self.report=report
        try:
            self.history.save(report)
            self.audit.record({'completed':'scan-complete','cancelled':'scan-cancelled'}.get(report.get('status'),'scan-partial'),len(report.get('findings',[])))
        except OSError as exc:report.setdefault('issues',[]).append({'reason':'Rapor kaydedilemedi: '+str(exc)})
        state={'completed':'Tamamlandı','partial':'Kısmen tamamlandı','cancelled':'Durduruldu'}.get(report['status'],report['status'])
        self.status_label.setText(state);self.path_label.setText('Süre sınırına ulaşıldı; eldeki sonuçlar gösteriliyor.' if report.get('stop_reason')=='time_budget' else '')
        self.summary.setText(f"{state} · {len(report['findings'])} eşleşme · {report.get('indexed_files',len(report['files'])):,} dosya · {report.get('duration_seconds',0):.1f} sn")
        self.category.blockSignals(True)
        while self.category.count()>3:self.category.removeItem(3)
        for key,value in report.get('artifacts',{}).items():
            if isinstance(value,list):self.category.addItem(TITLES.get(key,key),key)
        self.category.setCurrentIndex(0);self.category.blockSignals(False);self.search.clear();self.refresh_results();self.navigate(1)
        if report.get('status')!='cancelled' or report.get('findings'):self.reveal.start(report)
    def refresh_results(self):
        if not self.report:return
        report=self.report;key=self.category.currentData();term=self.search.text().casefold()
        note='Tarama sürüyor; sonuçlar canlı güncellenir.' if report.get('status')=='running' else 'Eşleşme olmaması temiz cihaz garantisi değildir.'
        if key=='index':
            try:rows=search_files(report['index_path'],report['scan_id'],self.search.text()) if report.get('index_path') else []
            except (OSError,KeyError,ValueError,sqlite3.Error) as exc:rows=[{'reason':str(exc)}]
            note='Aramaya uyan ilk 500 kayıt gösterilir; tüm dosya adları yerel indekste tutulur.'
        elif key=='coverage':
            rows=report.get('components',[])+report.get('issues',[])+[{'path':p,'reason':report.get('exclusion_reasons',{}).get(p,'Kullanıcı tercihiyle kapsam dışında')} for p in report.get('excluded_paths',[])]
            note=f"{report.get('issues_total',len(report.get('issues',[]))):,} dosya erişim/kapsam kaydı. İçerik sınırları: 256 MiB/dosya, 30 sn/arşiv; bellek/DMA ve Procmon çekirdek izlemesi yok."
        elif key=='findings':
            rows=report['findings'];note='Statik dosya eşleşmeleridir; delil düzeyi ayrıdır. Çalıştırma, oyunda kullanım ve aktif özellik kanıtı değildir.'
        elif key=='method_coverage':
            rows=report.get('artifacts',{}).get(key,[]);note='50 yöntemin yetenek haritası. Kayıt bulunması eksiksiz tarama anlamına gelmez; desteklenmeyen alanlar ayrıca yazılır.'
        elif key=='review_signals':
            rows=report.get('artifacts',{}).get(key,[]);note='İnceleme gerektiren bağlam; yönetim/bakım işlemleri de bu izleri bırakabilir. Tek başına hile veya ceza kanıtı değildir.'
        else:rows=report.get('artifacts',{}).get(key,[]);note='Sistem kayıtlarıdır; tek başına hile kullanımı kanıtı değildir.'
        if key!='index' and term:rows=[row for row in rows if term in json.dumps(row,ensure_ascii=False).casefold()]
        self.model.set_rows(rows);self.result_note.setText(note)
        for i in range(self.model.columnCount()):self.result_table.setColumnWidth(i,240 if i==0 else 180)
    def open_details(self,index):
        if not index.isValid():return
        dialog=QDialog(self);dialog.setWindowTitle('Kayıt ayrıntısı');dialog.resize(760,480)
        layout=QVBoxLayout(dialog);text=QPlainTextEdit();text.setReadOnly(True)
        text.setPlainText(json.dumps(self.model.rows[index.row()],ensure_ascii=False,indent=2));layout.addWidget(text);dialog.exec()
    def export_report(self):
        if not self.report:return
        name,_=QFileDialog.getSaveFileName(self,'Sonuçları kaydet','AtlasAC-sonuclar.json','JSON (*.json)')
        if name:
            try:
                write_json(Path(name),minimize_report(self.report));self.audit.record('report-export')
            except OSError as exc:self.result_note.setText('Kaydedilemedi: '+str(exc))
    def clear_local_data(self):
        if self.worker and self.worker.isRunning():
            self.result_note.setText('Verileri silmeden önce taramayı durdur ve kapanmasını bekle.');return
        answer=QMessageBox.question(self,'Yerel verileri sil','Bu uygulamanın yerel raporları ve dosya indeksi silinsin mi? Dışa aktarılan kopyalar kapsam dışıdır.',QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No,QMessageBox.StandardButton.No)
        if answer!=QMessageBox.StandardButton.Yes:return
        try:
            count=self.history.purge()+purge_index(self.audit.base)+self.audit.purge()
            self.report=None;self.live_files=[];self.live_findings=[];self.model.set_rows([]);self.live_model.set_rows([])
            self.summary.setText('Yerel tarama verileri silindi.');self.result_note.setText(f'{count} yerel kayıt dosyası silindi. Dışa aktarılan kopyalar silinmedi.')
            self.status_label.setText('Hazır');self.path_label.clear()
        except OSError as exc:self.result_note.setText('Silme tamamlanamadı: '+str(exc))
    def resizeEvent(self,event):
        super().resizeEvent(event)
        if hasattr(self,'reveal'):self.reveal.setGeometry(self.background.rect())
    def changeEvent(self,event):
        super().changeEvent(event)
        if event.type()==QEvent.Type.WindowStateChange and hasattr(self,'reveal'):
            paused=self.isMinimized();self.background.set_window_visible(not paused)
            self.progress_bar.set_suspended(paused);self.reveal.set_suspended(paused)
    def closeEvent(self,event):
        if self.worker and self.worker.isRunning():self.closing=True;self.cancel_scan();event.ignore()
        else:self.background.movie.stop();event.accept()

TITLES={'review_signals':'İnceleme sinyalleri — hile kanıtı değil','method_coverage':'50 yöntem: kapsam ve eksikler','jvm_context':'JVM başlatma bağlamı','macro_context':'Makro araçları — envanter','name_context':'Dosya adı biçim kontrolleri','execution':'BAM çalıştırma kayıtları','commands':'PowerShell / CMD / kabuk komutları','command_coverage':'Komut kaydı kapsamı','history':'Tarayıcı geçmişi','downloads':'İndirmeler','startup':'Başlangıç','journal':'USN günlüğü','activity':'Etkinlik kayıtları','processes':'İşlemler','modules':'Modüller','autoruns':'Başlangıç','services':'Servisler','drivers':'Sürücüler','tasks':'Görevler','browser_history':'Tarayıcı geçmişi','browser_downloads':'İndirmeler','usb':'USB','events':'Olaylar','prefetch':'Prefetch','usn':'USN','bam':'BAM'}

def run_desktop(rules_path=RULES):
    app=QApplication.instance() or QApplication(sys.argv[:1]);app.setApplicationName('AtlasAC');app.setOrganizationName('AtlasOyuncu')
    for name in ('Poppins-Regular.ttf','Poppins-SemiBold.ttf'):QFontDatabase.addApplicationFont(str(ASSETS/name))
    app.setFont(QFont('Poppins',10));window=AtlasWindow(rules_path)
    if app.primaryScreen().availableGeometry().height()<850:window.showMaximized()
    else:window.show()
    return app.exec()
