Masaüstü taraması artık toplam süre dolunca otomatik durmaz. Tarama tamamlanana veya kullanıcı Durdur’a basana kadar sürer; ekrandaki “En fazla 10 dakika” ifadesi kaldırıldı.

CLI `--system-scan` da varsayılan olarak toplam süre sınırı olmadan çalışır. İstenirse `--max-seconds SANİYE` ile açık bir süre sınırı verilebilir; 590 saniyeye kırpılmaz. Geçersiz süreler işlem başlatılmadan reddedilir. Ayrı eski `--scan KLASÖR` okuyucusunun bütçeleri değişmedi.

Durdur işlemi, canlı sonuçlar, CPU hedefi ve yerel bütünlük denetimleri korunur. Tek dosya/arşiv sınırına takılan içerik kısmi olarak kaydedilir; diğer dosyaların taranması devam eder. Toplam süre sınırının kalkması, her dosyanın okunabildiği veya tüm hilelerin bulunduğu anlamına gelmez.
