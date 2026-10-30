"""Auditable M01–M50 capability map. A listed method is not an implemented detector."""
import os

# id, title, capability, platform, available inputs, unimplemented remainder
METHODS=[
('M01','Oyun dizini / modlar','partial','all','file_index','Aktif oyun dizini disk eşleşmeleriyle ilişkilendirilmez; config/log semantik analizi yok.'),
('M02','Geçici dizin / arşiv','partial','all','file_index','Arşiv dosyaları incelenir; geçici yoldan çalıştırma veya oturum bağlantısı kurulmaz.'),
('M03','AHK / makro','inventory-only','all','macro_context','İşlem/script yolu envanteri; makro davranışı ve oyun kullanımı çözülmez.'),
('M04','Görünmez / Unicode ad','context-only','all','name_context','Ulaşılan aday dosya/dizinlerde format kontrolleri; normal Unicode harfler işaretlenmez.'),
('M05','RedLotus disk / bellek yaklaşımı','partial','all','file_index','AtlasAC statik kuralları vardır; RedLotus motoru ve bellek analizi yok.'),
('M06','JAR / sınıf analizi','partial','all','file_index','Metadata, özgül sınıflar ve sınırlı backdoor deseni; genel decompile / davranış analizi yok.'),
('M07','JNI / JVMTI enjeksiyonu','not-implemented','all','','JNI/JVMTI bağlantısı ve enjekte edilmiş kod doğrulanmaz.'),
('M08','Ocean tespit türleri','partial','all','file_index','Bağımsız AtlasAC statik kuralları; Ocean motoru ve tüm uyarı türleri uygulanmadı.'),
('M09','İşlem / DLL / strings','inventory-only','all','processes modules','İşlem ve seçili modül yolları; bellek strings veya DLL zararlılık analizi yok.'),
('M10','DPS bellek analizi','not-implemented','windows','','DPS dökümü veya belleği okunmaz.'),
('M11','Prefetch','partial','windows','prefetch','Kaydedilen çalışma zamanları; ilgili dosya/volume referansları çözümlenmez.'),
('M12','LastActivity birleşik geçmiş','partial','all','execution prefetch events','Mevcut kaynaklar ayrı gösterilir; LastActivity motoru / otomatik zaman çizelgesi yok.'),
('M13','USN Journal','partial','windows','journal','Sınırlı ad/neden/referans; tam yol ve çalıştırma çıkarımı yok.'),
('M14','Replace / içerik değişimi','partial','all','file_index','Önbellekte içerik değişim doğrulaması; eski içerik kimliği veya manipülasyon kanıtı yok.'),
('M15','FAT / exFAT / USB kurtarma','inventory-only','all','usb connected_usb','USB envanteri; disk imajı, silinmiş veri kurtarma veya çıkarılmış aygıt içeriği yok.'),
('M16','PowerShell / PSReadLine','partial','all','commands command_coverage review_signals','Erişilen kayıtlar ve kapsam gösterilir; tüm komutlar veya geçmişin silindiği garanti edilmez.'),
('M17','Servis durumu','inventory-only','windows','services','Durum envanteri; durmuş veya trigger-start servis hile sayılmaz.'),
('M18','Registry bağlamı','partial','windows','startup usb execution','Run/USB/BAM alt kümesi; MRU/PCA/MuiCache/WordWheelQuery yok.'),
('M19','Ağ / WiFi / MAC','not-implemented','all','','Ağ değişimi, hotspot veya MAC ile hile kimliği çıkarılmaz.'),
('M20','BAM / PCA','partial','windows','execution','BAM kayıtları; PCA yok, geçmiş yol mevcut dosyanın kimliğini kanıtlamaz.'),
('M21','DiagTrack / Appinfo belleği','not-implemented','windows','','Servis belleği okunmaz.'),
('M22','Amcache / ActivitiesCache / SRUM','not-implemented','windows','','Bu veritabanları ayrıştırılmaz.'),
('M23','UserAssist','not-implemented','windows','','UserAssist çözümlemesi yok.'),
('M24','Defender / ShellBags / kaldırma / DLL','inventory-only','all','modules','Yalnız seçili modül yolları; Defender geçmişi, ShellBags ve kaldırma kayıtları yok.'),
('M25','AMD apprecord.csv','not-implemented','windows','','AMD kayıt biçimi ayrıştırılmaz; bulunmaması şüphe değildir.'),
('M26','Görüntüleyici filtreleri','context-only','all','method_coverage','AtlasAC kapsam/sınırları raporlanır; üçüncü parti araç ayarları denetlenmez.'),
('M27','hosts / DNS / AutoRun','not-implemented','all','','Bu ayarlar analiz edilmez; tek başına hile kanıtı sayılmaz.'),
('M28','Prefetch ayarı / dosya özniteliği','not-implemented','windows','','Prefetch ayar geçmişi ve öznitelik manipülasyonu doğrulanmaz.'),
('M29','Silinmiş BAM kurtarma','not-implemented','windows','','Silinmiş Registry anahtarı kurtarılmaz.'),
('M30','Günlük / journal temizliği','partial','all','commands command_coverage review_signals','Erişilen temizleme komutu/olayı inceleme sinyalidir; silinen içerik ve niyet bilinmez.'),
('M31','Geri dönüşüm / zaman anomalisi','not-implemented','all','','Geri dönüşüm içeriği ve zaman manipülasyonu analizi yok.'),
('M32','Servis thread / BAM sürücüsü','inventory-only','windows','drivers','Sürücü envanteri; askıya alınmış thread veya müdahale doğrulaması yok.'),
('M33','Gerçek JVM argümanları','inventory-only','all','jvm_context','Erişilen canlı argv içindeki seçili seçenekler; launcher profili veya agent kimliği çözülmez.'),
('M34','Fileless / scriptblock','partial','all','commands command_coverage','Erişilen scriptblock/komut kayıtları; bellekte fileless payload tespiti yok.'),
('M35','Run / RunOnce / Startup','inventory-only','all','startup','Başlangıç envanteri; hedefin oyun kullanımı veya zararlılığı çıkarılmaz.'),
('M36','StartupInfo XML','not-implemented','windows','','Tanılama XML içeriği ayrıştırılmaz; kendisi otomatik başlatma kaydı sayılmaz.'),
('M37','Alternate Data Streams','not-implemented','windows','','ADS taraması yok; Zone.Identifier hile kanıtı değildir.'),
('M38','Zamanlanmış görevler','inventory-only','windows','tasks','Eylem/argüman/çalışma dizini; hesap bağlamı ve payload kimliği çözülmez.'),
('M39','WMI / WMIC','partial','windows','commands','Erişilen komut metni; WMI kalıcılık aboneliği veya kullanım niyeti çözülmez.'),
('M40','Hedefli bellek strings','not-implemented','all','','Bellek byte/string taraması yok.'),
('M41','Jarabel sınıf analizi','partial','all','file_index','Bağımsız AtlasAC statik sınıf kuralları; Jarabel motoru veya genel işlev çıkarımı yok.'),
('M42','Dökümden dosya yolları','not-implemented','all','','Döküm yol ayıklama / device-path eşleme yok.'),
('M43','Kernel / ham RAM / süreç dökümü','not-implemented','all','','Bellek dökümü alma veya ayrıştırma yok.'),
('M44','PE / packer / import analizi','partial','all','file_index','Başlık ve bilinen tam dosya hashleri; PE yapısı/import/packer veya enjeksiyon analizi yok.'),
('M45','Autopsy / disk imajı','not-implemented','all','','Disk imajı ve silinmiş dosya kurtarma yok.'),
('M46','Registry hive / silinmiş kayıt','not-implemented','windows','','Çevrimdışı hive ve silinmiş Registry kaydı çözülmez.'),
('M47','Şifreli volume','not-implemented','all','','Kapalı/şifreli volume açılmaz; şifreleme hile kanıtı değildir.'),
('M48','Artefact / timeline / Hayabusa','partial','all','events commands execution prefetch journal','Kaynaklar ayrı gösterilir; genel korelasyon, Hayabusa ve bağımsız kanıt skoru yok.'),
('M49','JavaLauncher / Prefetch JAR yolları','inventory-only','all','jvm_context','Canlı -jar/-cp yolu envanteri; JavaLauncher.log, Prefetch ilişkili JAR ve bellek yolları yok.'),
('M50','Çok amaçlı araç / kimlik','inventory-only','all','processes usb','İşlem/USB envanteri; kişi kimliği, niyet veya hile kullanımı çıkarılmaz.'),
]


def coverage(report, platform=None):
    windows=(os.name=='nt') if platform is None else platform=='windows'
    artifacts=report.get('artifacts',{});result=[]
    for method,title,capability,target,sources,gap in METHODS:
        inputs=sources.split();present=[];records=0
        for key in inputs:
            if key=='file_index':
                if report.get('index_path'):present.append(key);records+=report.get('indexed_files',0)
            elif key=='method_coverage':present.append(key)
            elif key in artifacts:
                present.append(key);records+=len(artifacts[key])
        state=('not-applicable' if target=='windows' and not windows else
               'unsupported' if capability=='not-implemented' else
               'records-available' if records else 'no-records' if present else 'not-collected')
        result.append({'method_id':method,'name':title,'capability':capability,'platform':target,
                       'collection_status':state,'sources_present':present,'records':records,'gap':gap,
                       'note':'Kaynağın bulunması, toplamanın eksiksizliği veya hile kullanımı anlamına gelmez; erişim hataları kapsam bölümündedir.'})
    return result
