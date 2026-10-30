# Rehberdeki 50 yöntemin gerçek kapsamı — 0.3.7

Bu liste 50 yöntemin uygulanmış olduğunu söylemez. `partial`: yalnız belirtilen alt küme; `inventory-only`: envanter; `context-only`: bağlam; `not-implemented`: destek yok. Kaynak varlığı eksiksiz toplama veya hile kanıtı değildir. Her rapordaki `method_coverage`, bu yetenek haritasını o taramada mevcut kaynaklarla birleştirir. Sayılar kaynak kayıtlarıdır; bağımsız kanıt sayısı veya güven puanı değildir.

Kaynak rehber: `AtlasOyuncu-AAC-Rehberi.md`; SHA-256: `b78f179aa4bcd435e4073ce1883f8c30f001c9bac38bde0a0a0e2339709614c3`. Rehber ve özel görev konuşmaları uygulamayla dağıtılmaz.

| Yöntem | Yetenek | Platform | Kullanılan alt küme / sınır |
|---|---|---|---|
| M01 Oyun dizini / modlar | partial | all | Aktif oyun dizini disk eşleşmeleriyle ilişkilendirilmez; config/log semantik analizi yok. |
| M02 Geçici dizin / arşiv | partial | all | Arşiv dosyaları incelenir; geçici yoldan çalıştırma veya oturum bağlantısı kurulmaz. |
| M03 AHK / makro | inventory-only | all | İşlem/script yolu envanteri; makro davranışı ve oyun kullanımı çözülmez. |
| M04 Görünmez / Unicode ad | context-only | all | Ulaşılan aday dosya/dizinlerde format kontrolleri; normal Unicode harfler işaretlenmez. |
| M05 RedLotus disk / bellek yaklaşımı | partial | all | AtlasAC statik kuralları vardır; RedLotus motoru ve bellek analizi yok. |
| M06 JAR / sınıf analizi | partial | all | Metadata, özgül sınıflar ve sınırlı backdoor deseni; genel decompile / davranış analizi yok. |
| M07 JNI / JVMTI enjeksiyonu | not-implemented | all | JNI/JVMTI bağlantısı ve enjekte edilmiş kod doğrulanmaz. |
| M08 Ocean tespit türleri | partial | all | Bağımsız AtlasAC statik kuralları; Ocean motoru ve tüm uyarı türleri uygulanmadı. |
| M09 İşlem / DLL / strings | inventory-only | all | İşlem ve seçili modül yolları; bellek strings veya DLL zararlılık analizi yok. |
| M10 DPS bellek analizi | not-implemented | windows | DPS dökümü veya belleği okunmaz. |
| M11 Prefetch | partial | windows | Kaydedilen çalışma zamanları; ilgili dosya/volume referansları çözümlenmez. |
| M12 LastActivity birleşik geçmiş | partial | all | Mevcut kaynaklar ayrı gösterilir; LastActivity motoru / otomatik zaman çizelgesi yok. |
| M13 USN Journal | partial | windows | Sınırlı ad/neden/referans; tam yol ve çalıştırma çıkarımı yok. |
| M14 Replace / içerik değişimi | partial | all | Önbellekte içerik değişim doğrulaması; eski içerik kimliği veya manipülasyon kanıtı yok. |
| M15 FAT / exFAT / USB kurtarma | inventory-only | all | USB envanteri; disk imajı, silinmiş veri kurtarma veya çıkarılmış aygıt içeriği yok. |
| M16 PowerShell / PSReadLine | partial | all | Erişilen kayıtlar ve kapsam gösterilir; tüm komutlar veya geçmişin silindiği garanti edilmez. |
| M17 Servis durumu | inventory-only | windows | Durum envanteri; durmuş veya trigger-start servis hile sayılmaz. |
| M18 Registry bağlamı | partial | windows | Run/USB/BAM alt kümesi; MRU/PCA/MuiCache/WordWheelQuery yok. |
| M19 Ağ / WiFi / MAC | not-implemented | all | Ağ değişimi, hotspot veya MAC ile hile kimliği çıkarılmaz. |
| M20 BAM / PCA | partial | windows | BAM kayıtları; PCA yok, geçmiş yol mevcut dosyanın kimliğini kanıtlamaz. |
| M21 DiagTrack / Appinfo belleği | not-implemented | windows | Servis belleği okunmaz. |
| M22 Amcache / ActivitiesCache / SRUM | not-implemented | windows | Bu veritabanları ayrıştırılmaz. |
| M23 UserAssist | not-implemented | windows | UserAssist çözümlemesi yok. |
| M24 Defender / ShellBags / kaldırma / DLL | inventory-only | all | Yalnız seçili modül yolları; Defender geçmişi, ShellBags ve kaldırma kayıtları yok. |
| M25 AMD apprecord.csv | not-implemented | windows | AMD kayıt biçimi ayrıştırılmaz; bulunmaması şüphe değildir. |
| M26 Görüntüleyici filtreleri | context-only | all | AtlasAC kapsam/sınırları raporlanır; üçüncü parti araç ayarları denetlenmez. |
| M27 hosts / DNS / AutoRun | not-implemented | all | Bu ayarlar analiz edilmez; tek başına hile kanıtı sayılmaz. |
| M28 Prefetch ayarı / dosya özniteliği | not-implemented | windows | Prefetch ayar geçmişi ve öznitelik manipülasyonu doğrulanmaz. |
| M29 Silinmiş BAM kurtarma | not-implemented | windows | Silinmiş Registry anahtarı kurtarılmaz. |
| M30 Günlük / journal temizliği | partial | all | Erişilen temizleme komutu/olayı inceleme sinyalidir; silinen içerik ve niyet bilinmez. |
| M31 Geri dönüşüm / zaman anomalisi | not-implemented | all | Geri dönüşüm içeriği ve zaman manipülasyonu analizi yok. |
| M32 Servis thread / BAM sürücüsü | inventory-only | windows | Sürücü envanteri; askıya alınmış thread veya müdahale doğrulaması yok. |
| M33 Gerçek JVM argümanları | inventory-only | all | Erişilen canlı argv içindeki seçili seçenekler; launcher profili veya agent kimliği çözülmez. |
| M34 Fileless / scriptblock | partial | all | Erişilen scriptblock/komut kayıtları; bellekte fileless payload tespiti yok. |
| M35 Run / RunOnce / Startup | inventory-only | all | Başlangıç envanteri; hedefin oyun kullanımı veya zararlılığı çıkarılmaz. |
| M36 StartupInfo XML | not-implemented | windows | Tanılama XML içeriği ayrıştırılmaz; kendisi otomatik başlatma kaydı sayılmaz. |
| M37 Alternate Data Streams | not-implemented | windows | ADS taraması yok; Zone.Identifier hile kanıtı değildir. |
| M38 Zamanlanmış görevler | inventory-only | windows | Eylem/argüman/çalışma dizini; hesap bağlamı ve payload kimliği çözülmez. |
| M39 WMI / WMIC | partial | windows | Erişilen komut metni; WMI kalıcılık aboneliği veya kullanım niyeti çözülmez. |
| M40 Hedefli bellek strings | not-implemented | all | Bellek byte/string taraması yok. |
| M41 Jarabel sınıf analizi | partial | all | Bağımsız AtlasAC statik sınıf kuralları; Jarabel motoru veya genel işlev çıkarımı yok. |
| M42 Dökümden dosya yolları | not-implemented | all | Döküm yol ayıklama / device-path eşleme yok. |
| M43 Kernel / ham RAM / süreç dökümü | not-implemented | all | Bellek dökümü alma veya ayrıştırma yok. |
| M44 PE / packer / import analizi | partial | all | Başlık ve bilinen tam dosya hashleri; PE yapısı/import/packer veya enjeksiyon analizi yok. |
| M45 Autopsy / disk imajı | not-implemented | all | Disk imajı ve silinmiş dosya kurtarma yok. |
| M46 Registry hive / silinmiş kayıt | not-implemented | windows | Çevrimdışı hive ve silinmiş Registry kaydı çözülmez. |
| M47 Şifreli volume | not-implemented | all | Kapalı/şifreli volume açılmaz; şifreleme hile kanıtı değildir. |
| M48 Artefact / timeline / Hayabusa | partial | all | Kaynaklar ayrı gösterilir; genel korelasyon, Hayabusa ve bağımsız kanıt skoru yok. |
| M49 JavaLauncher / Prefetch JAR yolları | inventory-only | all | Canlı -jar/-cp yolu envanteri; JavaLauncher.log, Prefetch ilişkili JAR ve bellek yolları yok. |
| M50 Çok amaçlı araç / kimlik | inventory-only | all | İşlem/USB envanteri; kişi kimliği, niyet veya hile kullanımı çıkarılmaz. |

Statik dosya tespiti; tam dosya hash, üye hash, sınıf yapısı, namespace ve beyan edilmiş mod kimliği olarak ayrılır. Hiçbiri tek başına çalıştırma, aktif oyun özelliği veya sunucu oturumu bağlantısını kanıtlamaz. Normal AHK/agent/Unicode, durmuş servis, USB veya geçmişin bulunmaması hile sonucuna çevrilmez. Günlük temizleme kaydı ayrı inceleme sinyalidir. Aynı kaynak iki yerde görünürse bağımsız kanıt olarak puanlanmaz; uygulama otomatik kanıt skoru/ban üretmez.
