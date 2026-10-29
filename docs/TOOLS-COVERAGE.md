# AtlasAC 0.3.0 — sağlanan araçlarla kapsam karşılaştırması

Bu tablo, `/AAC Plus Plus/AAC Uygulamalar` içindeki dosya adlarından belirlenen inceleme alanlarını AtlasAC'nin kendi okuyucularıyla karşılaştırır. Harici EXE'ler AtlasAC tarafından çalıştırılmaz veya dağıtılmaz. Araçların tüm özelliklerinin kopyalandığı iddia edilmez.

| Araç / alan | AtlasAC'deki karşılığı | Sınır |
| --- | --- | --- |
| Everything | Tüm erişilebilir yerel dosyaların SQLite ad/boyut/zaman indeksi; ad araması | NTFS MFT indeksleyicisi veya anlık değişiklik aboneliği değildir. İlk tarama dosya sistemini dolaşır. |
| Process Explorer | PID, üst PID, yol, komut satırı, kullanıcı, başlangıç, RAM; oyun/launcher modül yolları | Tüm süreçlerde stack, handle, imza veya bellek incelemesi yok. Korumalı süreçler eksik kalabilir. |
| Autoruns | Windows Run/RunOnce, bazı sistem başlangıç Registry alanları; CIM servis/sürücü ve zamanlanmış görevleri | Tüm Autoruns kategorileri, tüm kullanıcı hive'ları ve imza doğrulaması yok. Linux autostart ve systemd bağlantıları ayrı okunur. |
| BrowsingHistoryView | Chromium/Firefox geçmiş kaydı; canlı WAL destekli salt okunur SQLite snapshot | Profil başına son 3000 kayıt; kilit/yetki sorunları raporlanır. Linux'ta mevcut kullanıcının profilleri aranır. |
| BrowserDownloadsView | Chromium indirmeleri/URL zinciri ve Firefox indirme annotation kayıtları | Firefox kayıtlarının varlığı sürüm/veritabanına bağlıdır; kayıt yokluğu hiç indirme yapılmadığını kanıtlamaz. |
| USBDeview | Windows USB/USBSTOR Registry geçmişi ve bağlı PnP USB envanteri; Linux bağlı USB sysfs | Registry değişiklik zamanı son takılma zamanı olarak yorumlanmaz. Linux tarihçe sağlamaz. |
| WinPrefetchView | SCCA/MAM Prefetch başlığı, yürütülebilir adı ve biçimden okunan zamanlar | Windows erişim yetkisi ve desteklenen sürüm biçimlerine bağlı; çalışma sayısı/volume bağımlılıkları çözülmez. |
| LastActivityView | BAM yürütme izleri, Prefetch ve seçilmiş son Windows sistem olayları | Tüm ShellBag, UserAssist, Amcache, SRUM, Jump List ve silinmiş kayıt analizi yok. |
| JournalTrace / journal-tool | NTFS USN v2/v3 ad, zaman, neden ve parent/file referansları | Salt okuma; yönetici yetkisi gerekebilir. 20.000 kayıt/sürücü başına 10 saniye. Tam yol çözümleme veya silinmiş içerik kurtarma yok. |
| Process Monitor | Karşılığı eklenmedi; sonuçlarda kullanılamıyor durumu | Çekirdek dosya/Registry/stack olay sürücüsü ve gerçek zamanlı izleme yok. |

Dosya içerik tespiti önceki doğrulanmış Minecraft kurallarını kullanır. Sistem kayıtları tek başına hile olarak işaretlenmez. Genel Trojan, oyun belleği ve DMA tespiti sağlanmaz.

Masaüstünde yalnızca **Tarama** ve **Sonuçlar** sayfaları bulunur. Sistem kayıtları Sonuçlar içindeki açılır filtreden seçilir. Ekrandaki dosya araması ilk 500 eşleşmeyi getirir; tam indeks yerel SQLite dosyasındadır. Sonuçlar JSON ile dışa aktarılabilir. Ağ gönderimi yoktur.
