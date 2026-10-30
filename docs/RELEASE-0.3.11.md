Masaüstü taraması artık toplam süre dolunca otomatik durmaz. Tarama tamamlanana veya kullanıcı Durdur’a basana kadar sürer; ekrandaki “En fazla 10 dakika” ifadesi kaldırıldı.

CLI `--system-scan` da varsayılan olarak toplam süre sınırı olmadan çalışır. İstenirse `--max-seconds SANİYE` ile açık bir süre sınırı verilebilir; 590 saniyeye kırpılmaz. Geçersiz süreler işlem başlatılmadan reddedilir. Ayrı eski `--scan KLASÖR` okuyucusunun bütçeleri değişmedi.

Durdur işlemi, canlı sonuçlar, CPU hedefi ve yerel bütünlük denetimleri korunur. Tek dosya/arşiv sınırına takılan içerik kısmi olarak kaydedilir; diğer dosyaların taranması devam eder. Toplam süre sınırının kalkması, her dosyanın okunabildiği veya tüm hilelerin bulunduğu anlamına gelmez.

[Windows ve Ubuntu kontrolleri](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41087831930) başarılı: Windows 96 test; Linux 95 test ve bir Windows özel testi atlaması. Her platformda 60 statik örnek kontrolü, paketlenmiş kod/kaynak dosyası karşılaştırması ve 3/3 rapor doğrulama denemesi geçti. Eski toplam sınırın ötesine devam etme testi gerçek tarama işlemi ve ilerletilmiş saat ile yapıldı. [Doğrulama ayrıntıları](https://github.com/ZeninKaanX/AtlasAC/blob/v0.3.11/docs/VALIDATION-0.3.11.md).
