# AtlasAC 0.3.4 — Komut izleri, DoomsDay ve okuyucu hızlandırması

Komut incelemesi dosyalardan önce çalışır. PowerShell PSReadLine, 400/800, 4103/4104, Security 4688/1102, System 104, kuruluysa PowerShellCore/Sysmon kayıtları ve canlı kabuk açılış komutları salt okunur alınır. Linux'ta Bash/Zsh/PowerShell geçmişi ve canlı kabuk açılışları okunur. Komutlar çalıştırılmaz, denetim ayarları değiştirilmez. Kayıtlar ve anti-forensics belirtileri canlı gösterilir; komut snapshot'ı yalnızca bir kez aktarılır. Süre sonunda kısmi raporda da korunur. Sonuç listesinde komutlar/kapsam seçilebilir; ekran görüntüsü `preview-commands-fixture-034.png` yalnızca görsel fikstürdür.

Gerçek Windows testi (`windows-commands-real-034.json`): yalnız bu test için üretilen benzersiz geçici dosya PowerShell ile gerçekten silindi. Tam dosya yolu ile eşleştirilen gerçek Event 400 kaydı ve bir iz silme belirtisi bulundu. Gerçek çalışan CMD'nin özel test işareti açılış komutunda yakalandı (`live-command`). Security kanalı normal kullanıcıya erişim reddetti; geçmiş CMD komutları doğrulanmış sayılmadı. PowerShell Operational 200 olay sınırında kısmi, Sysmon/Core kanalları kurulu değil. Gerçek günlük veya kullanıcı geçmişi temizlenmedi; 1102/104 temizleme olayı semantiği XML fikstürüyle test edildi. Linux'ta mevcut gerçek geçmişten 47 satır, sıfır uyarı okundu (`linux-commands-real-034.json`, canlı süreç eklenmesinden önceki okuma); ham kişisel komutlar dışa aktarılmadı.

DoomsDay (`doomsday-real-034.json`): resmi sitenin normal ve rastgele boyutlu iki gerçek loader indirmesi **çalıştırılmadan** statik incelendi. Dış hash değerleri farklı; `net/java/f.class` ve `net/java/n.class` içeriklerinin iki SHA-256 değeri birlikte eşleşir. Sadece dosya adı, `dd` mod kimliği veya `net/java/` sınıf adları yeterli değildir. Linux'ta 2 canlı / 2 final eşleşme; yeni iki doğrulama aynı loader ailesinin iki resmi varyantıdır, iki ayrı hile ailesi sayılmaz. Bir sınıfın içeriği değişen normal test arşivi eşleşmedi. Gömülü `l.png` resmi ikon olarak alındı; toplam 18 ikon. Yeni sürüm/başka bytecode, silinmiş dosya ve bellekte kalan enjeksiyon için tespit garantisi yok; bütün ghost istemcilerini veya oyun belleğini kapsadığı iddia edilmez.

Okuyucu hızlandırması: namespace aramaları sıralı prefix aramasına çevrildi; dört kanıt ve iki farklı sınıf eşiği korunur. Windows native ChangeTime API tanımı tekrar oluşturulmaz, dosya başına gerçek ChangeTime yine okunur. CPU bütçesi ve 590 saniye sınırı aynı kaldı. `speed-034.json`: iki gerçek Linux JAR'ında 1,7614 → 1,6227 saniye; ilk Windows dört-JAR çifti 2,5805 → 3,1130 saniye ile daha yavaş çıktı. Ardından üç dönüşümlü Windows turunda medyan 2,8518 → 2,4008 saniye oldu (~%15,8). Bu küçük örnekler tam bilgisayar performansı değildir; GUI/komut toplama yoktur ve DoomsDay imzası eklenmeden önce ölçülmüştür. Ham ölçümlerin tamamı korunur; sadece hızlı tur seçilmez.

Windows son kaynak: aynı 58 testten 57 başarılı, symlink yetkisi isteyen 1 test atlandı (`windows-tests-034.txt`). Aynı resmi iki DoomsDay dosyası Windows’ta da iki canlı/iki final `member-sha256` eşleşmesi verdi (`windows-doomsday-real-034.json`). Önceki korpustan aynı üç pozitif/üç normal dosya yeni kurallarla tekrar denendi; üç canlı/final pozitif, normal dosyalarda sıfır eşleşme. Aynı altı dosyanın 18 kopyasında dokuz pozitif ve 12 arşiv tekrar kullanımı korundu (`windows-real-live-034.json`, `windows-real-copies-034.json`). Bunlar yeni bağımsız örnek sayısına eklenmez.

Son kaynak Linux testleri: 58/58 geçti (`linux-tests-034.txt`). Yeni testler: hedefli desenler, alıntı/yorum ve normal komutta uyarı vermeme, statik EncodedCommand çözümü, UTF-16 Windows hata metni, gerçek dosyayı değiştirmeden geçmiş okuma/temel sır maskeleme, kayıt yokluğunu şüphe saymama, komut belirtilerini dosyalardan önce yayınlama, süre sonu snapshot koruması, prefix kanıt eşdeğerliği ve çoklu arşiv üyesi SHA-256 kontrolü. Fikstürler gerçek hile örneği sayısına eklenmez.

Kayıt sınırları: son 7 gün, kanal başına 200 olay, en fazla 1200 komut, 32 geçmiş dosyası/son 1 MiB, geçmiş/canlı komutlar için ortak 400 satır bütçesi; komut görünümü 4096 karakter. Kesilen/çok parçalı kayıtlar kısmi sayılır; tam scriptblock yeniden birleştirme yoktur. CMD'nin bütün etkileşimli oturumları için genel kalıcı geçmiş yoktur. Denetim önceden kapalı/yetkisizse geçmişteki komutlar geri getirilemeyebilir. Geçmişe metin eklenebilir/değiştirilebilir; komut kaydı başarı veya kötü niyet kanıtı değildir. Eksik geçmiş silme kanıtı sayılmaz; AI'dan kod kopyalandığı belirlenmez. Yalnız yaygın anahtar=değer sır biçimleri maskelenir. Kaynaklar README'deki Microsoft belgeleridir.

Son tek dosyalık paketler kaynak modüller, güncel kural JSON'u ve 18 ikon dahil gömülü varlıklarla bytecode/içerik bazında karşılaştırıldı. WebEngine yoktur. Linux paketinde gerçek 3 saniyelik bütçe denemesi kısmi raporla bitti ve komut snapshot'ı korundu (`frozen-budget-034.json`). Son Windows paketinde gerçek 25 saniyelik sistem denemesi süre sınırında durdu; komut kayıtları/kapsam snapshot'ı korundu (`windows-frozen-budget-034.json`). Bunlar tam disk taraması değildir.

Aşağıdaki kayıtlar önceki sürümlere aittir.

# AtlasAC 0.3.3 — Arayüz CPU kullanımı

Arka planın ölçeklenmiş/koyulaştırılmış görüntüsü aynı GIF karesi ve pencere boyutunda tekrar kullanılır. Sonuç ekranının sabit başlığı/ışığı da kare bazında önbelleklidir. Opaque sonuç ekranı görünürken arkasındaki GIF durur; küçültülmüş pencerede animasyon zamanlayıcıları bekler. Geri açınca sonuç kaybolmaz; yalnızca Sonuçlar düğmesi kapatır. Balık ve köpek balığı hareketinin 16 ms zamanlayıcısı, grafikler, ses, taranan dosya türleri ve tespit kuralları korunmuştur.

Linux karşılaştırması: aynı cihazda 0.3.2 kaynak kopyasıyla iki dönüşümlü önce/sonra turu; her durumda 1,2 saniye ısınma ve 4 saniye ölçüm. 1280×860 Qt offscreen arayüzü, **tarama yapılmadan**, process_time/duvar saati ile ölçüldü. Ortalama bir çekirdek yüzdeleri: beklemede 10,07 → 7,86; balıklı çubukta 52,21 → 16,60; sonuçta 77,85 → 13,53; küçültülünce 10,03 → 0,39. Balıklı çubuğun arayüz CPU yükü %68,2, sonuç ekranının %82,6 azaldı. Bunlar Görev Yöneticisi toplam makine yüzdeleri değildir; gerçek taramada okuyucu CPU tüketimi ayrıca eklenir. Donanımlar arasında sabit toplam CPU sınırı vaat edilmez. Ham ölçümler ve kapsam `cpu-ui-033.json`, yeniden üretim aracı `tools/profile_ui_cpu.py`.

Linux: 49/49 test başarılı (`linux-tests-033.txt`). Windows: aynı 49 testten 48 başarılı, symlink yetkisi isteyen 1 test atlandı (`windows-tests-033.txt`). Yeni test, arka plan karesinin tekrar kullanımı/boyut değişiminde yenilenmesi, sonuç sırasında GIF'in durması, küçültme/geri açmada sonuç korunması ve küçültülmüş pencereye yeni sonuç ulaşmasını kontrol eder. Görseller yalnızca ekran fikstürleriyle incelendi (`preview-cpu-fish-033.png`, `preview-cpu-reveal-033.png`); yeni gerçek hile örneği doğrulaması sayılmaz.

Tarama okuyucuları da ortak süreç CPU bütçesiyle sınırlandı: mantıksal işlemci başına %5, toplam en fazla 0,6 çekirdek hedefi; iki okuma iş parçacığı. Dolaşım, hash blokları ve arşiv/iptal kontrol noktaları aynı bütçeyi paylaşır. 20 ms CPU patlama payı ve 2 ms kontrol aralığı vardır; büyük tek bir okuma/açma işlemi veya harici kayıt komutları anlık hedefi aşabilir. OS tarafından dayatılan toplam uygulama CPU tavanı değildir. İptal, bütçe beklemesini keser; 590 saniyelik süre sınırı korunur. Düşük bütçe taramayı uzatabilir ve aynı sürede daha az dosyaya ulaşabilir; kısmi sonuç Temiz sayılmaz.

`cpu-scan-033.json`: gerçek ViaFabricPlus 4.4.15 ve Sodium 0.8.15-beta.1 dosyaları, SHA-256 doğrulamalı aynı içerik, ayrı boş indeksler. Linux eski: 0,6024 sn / 0,6707 CPU sn; yeni: 1,8644 sn / 0,7662 CPU sn. Ortalama tarayıcı yükü 1,1133 çekirdekten 0,4109 çekirdeğe indi; iki dosya da tamamlandı, sıfır eşleşme/sıfır okuma sorunu. Küçük iki dosyalık CPU/hız takası ölçümüdür, tüm disk garantisi değildir. Arayüz ve sistem kayıt komutları bu ölçüme dahil değildir. Yeni eşzamanlı bütçe testi üç çalışan toplamının bütçeyi paylaştığını ve iptalin beklemeyi kestiğini sınar.

Windows VM (4 mantıksal işlemci): aynı gerçek 4 normal JAR ve ayrı soğuk indekslerle tarayıcı yükü 1,2468 çekirdek → 0,2018 çekirdek (%83,8 düşüş); süre 0,3258 → 1,3161 saniye. Hepsi tamamlandı; sıfır eşleşme/sıfır sorun. Bunlar küçük dosya gruplarıdır. Aynı kaynaklarla arayüz ölçümünde balıklı çubuk 0,9747 → 0,2418 çekirdek, sonuç 1,1249 → 0,2298 çekirdek oldu (`cpu-ui-033.json`). GUI/scan ölçümleri ayrı yapıldı; toplanıp ölçülmüş bütün-uygulama CPU sonucu sayılmaz.

`windows-real-live-033.json`: önceki korpustan SHA-256 doğrulanmış üç pozitif ve üç normal dosya, bütçeli okuyucuyla yeniden denendi. Üç pozitif de canlı/final raporda, normal dosyalarda sıfır eşleşme, okuma sorunu yok. Aynı altı dosyanın 18 kopyasında 9 doğru eşleşme ve 12 arşiv önbelleği kullanımı korundu (`windows-real-copies-033.json`). Yeni hile ailesi/örnek sayısına eklenmez.

Aşağıdaki kayıtlar önceki sürümlere aittir.

# AtlasAC 0.3.2 — Minecraft görselleri, kontrollü sonuç ekranı ve hızlandırma

Linux: 47/47 kaynak testi geçti (`linux-tests-032.txt`). Yeni çene testi gövde aynı konumdayken çenenin farklı karelerde hareket ettiğini, balıkların köpek balığının yarı boyundan küçük olduğunu denetler. Ses bittikten 6,25 saniye sonra sonuç animasyonu açık kalır; Sonuçlar düğmesiyle kapanır. Önceki otomatik kapanış davranışı kaldırıldı.

`real-live-032.json`: SHA-256 değerleri doğrulanan 3 gerçek pozitif ve 3 gerçek normal dosya tekrar indirildi, statik olarak incelendi. İlk turda 3 canlı ve 3 final eşleşme; bu altı dosyanın toplam 18 kopyasında 9 doğru pozitif, normal dosyalarda sıfır eşleşme, 12 içerik önbelleği kullanımı, sıfır okuma sorunu. Yeni bağımsız örnek sayısı değildir.

`speed-032.json`: kurulu gerçek ViaFabricPlus ve Sodium JAR’larının altışar kopyasıyla, optimize ve eski okuma üçer kez dönüşümlü karşılaştırıldı. Medyan 10.8562 saniyeden 1.9348 saniyeye düştü. Yalnızca aynı içeriğin tekrarlandığı bu ölçüm içindir; tüm bilgisayar için aynı oran iddia edilmez. Her dosyanın SHA-256 değeri ayrıca doğrulanır, dosya yolları korunur, kısmi okumalar ve okuma sırasında değişen dosyalar yeniden kullanılmaz; yarış durumu ayrıca test edildi.

`frozen-budget-032.json`: son tek dosyalık Linux paketinde gerçek sistem taraması iki saniyelik test sınırında kısmi sonuçla sonlandı. Sonuç animasyonundaki kullanıcı beklemesi tarama süresine dahil değildir. Gerçek Linux arayüzüyle yapılan tam disk denemesi de 590,046 saniyede sınırda durdu: 132.155 aday dosya, 286.959 normal dosya atlama, 167 tekrar arşiv kullanımı, 16 eşleşme (`linux-full-budget-032.json`). Kapsam tamamlanmadığından sonuç kısmi olarak saklandı. Son Windows EXE arayüzünde laboratuvarın gerçek dosyalarıyla 270 eşleşme görüldü; durdurma sonrası animasyon otomatik kapanmadı, Sonuçlar düğmesi bekledi (`preview-windows-held-032.png`). Bu 270 eşleşme ayrı hile ailesi sayısı değildir. İstemci ikonları 17’ye çıkarıldı; resmi ikon bulunamayanlarda gömülü PNG/Atlas logosu kullanılır.

Windows 0.3.2: aynı 47 test çalıştı; 46 başarılı, symlink oluşturma yetkisi isteyen 1 test atlandı. SHA-256 doğrulanmış aynı altı gerçek dosyada 3 canlı/3 final eşleşme; 18 kopyada 9 doğru eşleşme ve 12 arşiv tekrar kullanımı doğrulandı (`windows-real-live-032.json`, `windows-real-copies-032.json`). Sanal makinede fiziksel ses çıkışı doğrulanmadı. Aşağıdaki tarihsel kayıtlar 0.3.1 ve öncesine aittir.

# AtlasAC 0.3.1 güncellemesi — 29 Ekim 2026

Linux kaynak testleri: 43/43 geçti. Windows’ta aynı 43 test çalıştırıldı: 42 başarılı, symlink oluşturma yetkisi isteyen 1 test atlandı (`windows-tests-031.txt`). Yerel Linux ses aygıtlarıyla sesli animasyonun tamamlanıp kapandığı doğrulandı; Windows sanal makinesinde fiziksel ses çıkışı doğrulanmadı. Yeni senaryolar: çocuk süreçte takılan okuyucunun zorla sonlandırılması, canlı gerçek eşleşmeler, PNG atlama, oyun/önbellek alanında JAR tarama, sonuç ekranına bitmeden erişim, balık animasyonu ve 175 karelik sesli bitiş akışı, gömülü ikon okuma/boyut sınırı, eksik ikon için logo, farklı kural ikonları ve temiz balık sürüsü. Animasyonlar ayrıca yerel Qt görüntüleriyle incelendi.

Son Windows tek EXE paketinde gerçek sistem taraması sırasında 3.060 aday dosya ve 143 canlı eşleşme gözlendi; Sonuçlar sekmesine tarama bitmeden geçildi (`preview-windows-live-results-031.png`). Bunlar laboratuvardaki aynı örneklerin/kuralların eşleşmeleridir, 143 ayrı hile ailesi değildir.

`real-live-031.json`: mevcut hash doğrulanmış gerçek derlemelerden üç pozitif ve üç normal dosya yeniden sınandı; 3/3 pozitif canlı ve final raporda, normal dosyalarda sıfır eşleşme. Bunlar önceki örneklerden seçilmiştir, yeni bağımsız örnek sayısına eklenmez. `frozen-budget-031.json`: paketli Linux uygulamasında 2 saniyelik gerçek sistem taraması süre sınırında kısmi döndü.

Hızlı sistem modu artık görüntü/medya/belgeleri atlar; aşağıdaki tarihsel görüntü içine gizleme testleri eski klasör okuyucusu içindir. Genel 200 aile/tüm hile garantisi sağlanmaz.

# AtlasAC 0.3.0 doğrulaması — 29 Ekim 2026

Hazır Windows EXE üzerinde gerçek Başlat → Durdur → Sonuçlar akışı da kontrol edildi: 409 dosya, 8.9 saniye, açıkça **Durduruldu** durumu; temiz cihaz sonucu sayılmaz. 1280×800 ekranda E.V. ve iki gezinme düğmesi görünür kaldı. `preview-windows-030.png` / `preview-windows-cancelled-030.png`.

Yeni masaüstü iki sayfadır: Tarama/Sonuçlar. Qt arayüzünde gerçek worker ile yeniden adlandırılmış arşiv taraması, sonuç gösterimi, yerel rapor kaydı, boş disk kapsamı ve şeffaf logo kontrol edildi. E.V. etiketi sabittir. Yeni sistem tarayıcısı Minecraft dizinleri dışında da bütün yerel diskleri dolaşır; eski klasör tarama bütçesine bağlı değildir.

Linux: **32/32 test** geçti. Windows VM: **31 test geçti, 1 sembolik bağlantı testi yetki nedeniyle atlandı**. Kaydedilen çıktılar `linux-tests-030.txt`, `windows-tests-030.txt`. Test fikstürleri gerçek hile örneği sayısına eklenmez.

Yeni testler: 601 dosyanın tam indekslenmesi, 500 satırlık ekran arama sınırının tam taramayı kesmemesi, değişmemiş içerik önbelleği, aynı boyut ve geri yüklenmiş mtime ile değişen içeriğin yeniden okunması, kural değişikliğinde önbelleğin geçersizleşmesi, iptal/boş disk durumları, açık WAL veritabanından salt okunur snapshot, USN v2/v3 sınırları ve SCCA başlığı. USN/SCCA fikstür testleri gerçek Windows kayıtlarıyla aynı şey değildir.

Sağlanan AAC klasörü üzerinde gerçek dosya envanteri ölçümü: 13 dosya, 11 PE adayı. Soğuk tur 0.029 sn; önbellekli tur 0.013 sn, 13 cache hit ve 0 içerik okuma baytı. Bu **13 dosyalık küçük bir kapsamdır**, tüm bilgisayar hızı veya bu EXE'lerde genel zararlı tespiti ölçümü değildir. Ham ölçüm `systemscan-aac030.json`.

Yeni okuyucu Windows'taki önceki **297 benzersiz SHA-256** dosyasıyla yeniden denendi: **242 doğrulama + 15 geliştirme dosyası eşleşti; 40 normal modda 0 yanlış eşleşme; 0 okuma sorunu**. Süre: 366.706 saniye (Windows VM, eşzamanlı derleme/tarama yükü altında). Önceki manifestteki hash kümesi ve beklenen her sonuç tek tek karşılaştırıldı; `real-reader-030.json`. Bu dosyalar eski doğrulamaya yeni örnek olarak eklenmez.

Gerçek Windows sistem kayıtları, yönetici tokenı ile: 310 Prefetch (SCCA/MAM v31 örnekleri dahil), 20.000 USN (sınır nedeniyle kısmi), 264 servis, 393 sürücü, 224 görev, 112 olay, 45 BAM izi, 89 başlangıç ve 6 USB Registry kaydı. Yönetici olmadan korumalı alanların erişim hatası verdiği ayrı turda doğrulandı. Çıktılar `windows-records-admin-030.json` / `windows-records-user-030.json`. Bunlar tüm hilelerin yakalandığını ölçmez.

Açık Edge'de SQLite backup kilide takıldı. Yeni alternatif, veritabanı ve WAL/rollback journal dosyalarının değişiklik ve SHA-256 denetimli özel kopyasını okudu: **120 geçmiş ve 10 indirme kaydı**. Kaynak dosyaya yazılmaz; atomik backup olmadığı durum kısmi olarak işaretlenir. Özel URL veya komut satırları belgeye alınmadı; yalnızca sayımlar `windows-browser-030.json` içinde. Ek kilit testi dahil toplam 32 test vardır. Linux'ta 329 süreç, 454 oyun/uygulama modül yolu, 133 başlangıç kaydı, 15 bağlı USB ve 500 journal olayı alındı; `linux-records-030.json`.

Gerçek tüm disk denemeleri tamamlanmadan test amacıyla sonlandırıldı: Linux 353.500 dosya / 1227.3 sn; Windows 104.000 dosya / 1185.7 sn. **Bunlar tamamlanmış tam disk taramaları veya karşılaştırılabilir hız ölçümleri değildir.** Her iki SQLite indeksinde quick_check sonucu ok. Özetler `linux-full-disk-partial-030.json` ve `windows-full-disk-partial-030.json`. Özellikle büyük geliştirme arşivleri ilk taramayı uzatıyor; tam disk performans hedefi henüz doğrulanmadı. [Araçların özellik karşılaştırması](TOOLS-COVERAGE.md) tüm eşdeğerlik sınırlarını listeler. Önceki 242 örnek doğrulaması ve 76 türetim ölçümü aşağıda sürümüne bağlı tarihsel sonuçlardır; 200 ayrı hile ailesi garantisi sağlamaz.

---

# Doğrulama — 29 Ekim 2026, AtlasAC 0.2.1

## Tek dosyalık dağıtım

Windows `AtlasAC.exe` ve Linux `AtlasAC-Linux-x64` doğrudan açılan tek dosyalık uygulamalardır. Kurulum, hesap/key ve yanında `_internal` klasörü gerekmez. Gömülü logo, GIF, kurallar ve güncel doğrulama JSON'u paket içinden çıkarılmadan okunup kaynak SHA-256'larıyla karşılaştırıldı. HTML/WebEngine yükü bulunmadı. Her iki masaüstünde yerel pencere açılışı kontrol edildi. Tek Windows EXE ile 11 gerçek laboratuvar dosyasında 8 bulgu, 0 sorun ve tamamlandı sonucu alındı. Tek Linux çalıştırılabilir dosyası ayrıca SHA-256 doğrulanmış gerçek ForgeHax, Aoba ve Cigarette dosyalarında çalıştırıldı: 3 dosyada beklenen 3 istemci bulundu, 0 sorun kaydedildi. Bu üç dosya zaten ana veri kümesindedir ve 242 sayısına yeniden eklenmez. Çıktı: `linux-real-report.json`; kaynaklar: `linux-real-sources.json`. Ham örnekler dağıtılmaz.

## 0.2.1 sonuçları

10 yeni istemci kuralı, iki tam sınıfı birlikte gerektiren imza ve türevlerin çift etiketlenmesini önleyen kontrol eklendi. Aynı sınıfın yinelenen ZIP kayıtları iki ayrı sınıf sayılmaz. Linux'ta **26 test** geçti. Windows'ta **25 test** geçti, sembolik bağlantı yetkisi gerektiği için **1 test atlandı**. Çıktılar `linux-tests.txt` / `windows-tests.txt` dosyalarındadır.

257 resmi release dosyasının 15'i kural geliştirmeye ayrıldı. Kalan **242 benzersiz doğrulama dosyasının 242'si beklenen grupla eşleşti**. **17 adlandırılmış istemci grubu**, otomasyon ve eklentilerle **19 grup** bulunur. Bunlar 242 ayrı hile veya bağımsız mimari değildir; 200 farklı istemci hedefi karşılanmamıştır. Tüm indirmeler edinildi, yinelenen SHA-256 veya eksik tarama kaydı yoktu. 40 gerçek normal modda **0 yanlış eşleşme** görüldü.

19 grubun gerçek dosyalarıyla 76 gizleme denemesinin ilk turunda **75/76** tamamlandı. Yaklaşık 155 MiB Combatant arşivi dış ZIP içinde 64 MiB iç arşiv sınırına takılıyordu. İç arşiv sınırı 256 MiB'ye çıkarıldı; toplam arşiv ağacının **256 MiB**, **30 saniye**, **30.000 üye** ve **2 iç seviye** bütçesi korundu. Yeniden testte **76/76** tamamlandı ve iz bulundu. Bu, metadata kaldırılmış her türevin kesin marka adını saptama testi değildir; istemci izini bulmayı ölçer. Türetilmiş dosyalar 242 benzersiz doğrulama dosyasına eklenmez.

Dört değiştirilmiş eklentide aynı bilinen Java backdoor deseni **4/4** eşleşti. Örnekler çalıştırılmadı. Önceki 0.2.0 sonuçları `corpus/results/v0.2.0.json`, ilk genişletilmiş gizleme sonucu `extended-bypass-before.json`, güncel veriler `latest.json` içindedir.

Aşağıdaki bölümler ilk 0.2.0 ölçümünün tarihçesidir.


## Yerel masaüstü

Qt Widgets kullanılır. Hesap/PIN/key oluşturulmaz; tarayıcı, WebView, HTML raporu veya HTTP paneli açılmaz. Başlat düğmesi gerçek tarama iş parçacığını başlatır; sonuçlar aynı pencerede gösterilir. JSON rapor/geçmiş yereldir.

Linux’ta 22 birim ve masaüstü bütünleşme testi geçti. Testler mod/metadata/sınıf/hash eşleşmeleri, yeniden adlandırma, iç arşiv, görüntü öneki, bozuk ve büyük metadata, iptal, sembolik bağlantı, kapsamın birleştirilmesi, sınırlı yerel geçmiş ve gerçek Qt Başlat→sonuç akışını kapsar. Test fikstürleri gerçek hile örneği sayısına eklenmez. Windows VM’de 21 test geçti, sembolik bağlantı izni olmadığı için 1 test atlandı. Platform çıktıları `linux-tests.txt` ve `windows-tests.txt` dosyalarındadır.

## Gerçek Windows dosya testleri

İlk laboratuvarda üç kökte 11 aday dosya, 8 bulgu kaydı, 6 farklı kural bulundu. Meteor, Wurst, Baritone, BleachHack, ThunderHack ve Meteor Rejects örnekleri farklı adlarla, uzantılarla ve iç arşivlerde bulunuyordu. Aktif oyun veya sunucuda kullanım kanıtlanmadı. [İlk ölçüm](lab-results.json).

Genişletilmiş testin manifesti `corpus/candidates.json` dosyasındadır. 204 benzersiz resmi release dosyası edinildi; 4 geliştirme/keşif dosyası ayrıldı. Kalan **200 benzersiz SHA-256** doğrulama dosyasının **200’ü de beklenen aileyle eşleşti**, eksik tarama/indirme hatası yoktu. Altı istemci ailesi; Baritone ve Meteor Rejects dahil sekiz aile vardır. Aynı ailenin farklı sürümleri ayrı hile sayılmaz. Başlangıç kuralları 144/200 eşleşiyordu; ek kurallar ve eski Forge metadata okuması sonrası sonuç 200/200 oldu. Keşif ve doğrulama ayrımı gelecekteki bilinmeyen örneklere genelleme garantisi sağlamaz.

Normal karşı örnek manifesti `corpus/benign-candidates.json`: Sodium, Lithium, Iris, Fabric API, Mod Menu, FerriteCore, Cloth Config, Architectury API, Jade ve EntityCulling’in toplam **40 gerçek sürümünde 0 yanlış eşleşme**, 0 okuma/indirme hatası. Bu sonuç genel yanlış pozitif oranı değildir.

Sekiz aileden gerçek dosyalar üzerinde dört varyant: `.dat` olarak adlandırma, PNG öneki ekleme, `payload.bin` olarak dış ZIP’e koyma, metadata kaldırma. İlk denemede 30/32; iki dosya 16 MiB iç arşiv sınırına takıldı ve doğru biçimde kısmi gösterildi. İç arşiv sınırı 64 MiB’ye çıkarıldı, arşiv ağacının 256 MiB bütçesi korundu. Yeniden ölçüm **32/32 tamamlandı ve eşleşti**. Varyantlar bağımsız 200 dosyaya eklenmedi. Metadata kaldırılmış FDP’de aile kimliği kesinleşmeyebilir; bu test herhangi bir istemci izinin görülmesini ölçer.

MCHCC’nin değiştirilmiş WorldEdit, EssentialsX, EssentialsXChat ve ViaVersion dosyalarında Java sabit havuzu incelendi. Dört dosyada aynı tetikleyici ve sohbetten sunucu konsoluna komut ileten yöntem birleşimi bulundu. Kural **4/4** dosyada eşleşti; **tek bilinen desen** ölçüldü. Dört farklı Trojan ailesi veya genel RAT/stealer tespiti değildir. Örnekler yalnız VM’de statik okundu; yüklenmedi, import edilmedi veya çalıştırılmadı. Ham örnekler dağıtım paketlerinde yoktur.

Ölçümler `corpus/results/` altında; özet, hash, sürüm ve kaynak URL’leri uygulamanın Doğrulama ekranında görünür. Tüm sonuçlar dosya incelemesidir. **200 farklı hile ailesi hedefi ve evrensel yakalama garantisi karşılanmadı.**

Hazır Windows EXE ile otomatik seçilen üç klasör ayrıca tarandı: **11 dosya, 8 bulgu, 1 okuma sorunu**. Ocean indirme dosyası Windows tarafından okunamadı (`Errno 22`); sonuç doğru biçimde **kısmi tarama** olarak gösterildi. Altı kuralın izleri bulgularda yer aldı. Son derlemeyle tekrar taramada Ocean dosyası artık listede değildi; **11 dosya, 8 bulgu, 0 sorun, tamamlandı** sonucu alındı. [Gerçek EXE sonuç ekranı](preview-native-windows.png).

## Ocean karşılaştırması

Kullanıcının izin verdiği Windows VM’de resmi Ocean dosyasıyla gerçek tarama tamamlandı: **2 dakika 48 saniye, 46 log, 2 tespit, 2 uyarı**, panelde %44 risk. Oyun çalışmıyordu. Tespitler `Generic Bypass Method (CURL)` ve laboratuvardaki `BrowsingHistoryView.exe` için `UPX Packer`; uyarılar kapalı Memory Integrity ve açık Fast Boot idi. Altı ekilmiş mod bu koşullardaki tespit listesinde görünmedi. Bu, başka lisans/sürüm/oyun koşullarında Ocean başarımı hakkında genellenebilir ölçüm değildir. CURL veya UPX tek başına hile kullanımını kanıtlamaz.

Defender resmi Ocean dosyasını başlangıçta karantinaya aldı. Kullanıcının açık talebi üzerine yalnız VM’de gerçek zamanlı koruma geçici kapatıldı, testten sonra **yeniden açıldığı ekrandan doğrulandı**. AtlasAC uygulaması antivirüs ayarlarını değiştirmez. Ayrıntı: [Araştırma](RESEARCH.md).

## Güncel ölçümü yeniden üretme

Kontrollü laboratuvarda, örnekleri çalıştırmadan:

```bash
python tools/corpus_benchmark.py --manifest corpus/combined-candidates.json --cache /laboratuvar/cache --rules rules/default.json --output pozitif.json --workers 6
python tools/corpus_benchmark.py --manifest corpus/benign-candidates.json --cache /laboratuvar/cache --rules rules/default.json --output normal.json --workers 6
```

Araç yalnız resmi örnek dosyalarını indirir ve statik okur; oyun veya hile başlatmaz. SHA-256 yinelenen dosyaları ayırır, keşif dosyalarını doğrulama sayısına eklemez. Çıktıda tarayıcı motorunun kaynak SHA-256'sı ve kural dosyası SHA-256'sı da tutulur. Genel çıkış kodu, 200 ayrı istemci hedefi karşılanmadığından 2 olabilir; `positive_failed_or_partial`, `acquisition_errors` ve `false_positive_files` alanları gerçek dosya test hatalarını ayrıca belirtir.
