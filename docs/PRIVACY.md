# AtlasAC 0.3.11 — teknik gizlilik ve saklama

Kuruluş olarak kullanıcı tarafından belirtilen ad: **TrueFormTech**.
İletişim: **trueformtechx@gmail.com**. Teknik bilgilendirme sürümü: `2026-10-30.2`.

Bu belge hukuki uygunluk belgesi veya kuruluşun eksiksiz KVKK aydınlatma metni değildir. Kuruluşun tam hukuki kimliği/adresi, işleme şartı, alıcıları, hak başvuru yöntemi ve oyuncu/yaş bağlamı kuruluş tarafından netleştirilmelidir. Teknik izin kutusu bu değerlendirmeyi yapmaz. Metinle izin ayrı sunulur; kutu önceden seçilmez, reddetmek taramayı başlatmaz. Her taramada tekrar gösterilir. CLI, bilgilendirmeyi stderr üzerinden sunar ve `--consent` gerektirir.

## Toplanan alt küme

- Aday dosyaların yol/boyut/zaman/hash bilgileri, statik eşleşme ve erişim/kapsam kayıtları.
- İşlem ve seçili modül yolları; bilinen sır biçimleri maskelenmiş argv. Ayrı işlem kullanıcı adı alanı kaydedilmez; dosya yolları yine kullanıcı adı içerebilir.
- Erişilebilen son komut geçmişi, seçilmiş Windows kayıtları / Linux journal, başlangıç ve USB envanteri. Servis/USB/agent varlığı hile kullanımı kanıtı değildir.
- Yalnız mevcut kullanıcının profillerinden ilgili indirmeler: JAR/ZIP/EXE/DLL/SO/AHK/AU3/AppImage. URL kullanıcı bilgisi, sorgu ve fragment kaldırılır. Genel gezinme geçmişi rapordan çıkarılmıştır. Teknik SQLite snapshot tüm kaynak veritabanının geçici özel kopyasını içerebilir; kaynak değiştirilmez ve geçici kopya normal kapanışta temizlenir. Zorla kapanış/disk yedeği için adli silinme garantisi yoktur.
- Komutlarda assignment, flag, Bearer/Basic, Cookie ve desteklenen EncodedCommand biçimleri maskelenir. İsimsiz/özel kodlanmış sırlar veya URL yoluna gömülü sırlar her zaman tanınamaz; paylaşmadan önce inceleme gerekir.

## Saklama ve erişim

Raporlar en fazla 50 adet / 7 gün; dosya indeksinde son görülmeden itibaren 7 gün; içeriksiz işlem günlüğü en fazla 2000 olay / 7 gün. Zaman kontrolü uygulama açılışı, tarama veya günlüğe yazma sırasında yapılır. Uygulama kapalıyken zamanlayıcı yoktur. Önceki indeks şeması tarih taşımadığından eski önbellek ilk geçişte sıfırlanır; kaynak dosyalar etkilenmez.

Mevcut raporlar açılışta maskelenir, genel gezinme geçmişi kaldırılır, yaşları korunur. 16 MiB üzerindeki eski raporların içeriği otomatik ayrıştırılmaz; izinleri kısıtlanır ve yaş/adet sınırı uygulanır. Bu dosyalar paylaşılmadan önce silinmeli veya elle gözden geçirilmelidir.

POSIX dizin/dosya izinleri 700/600; Windows korumalı DACL mevcut süreç kullanıcısı ve SYSTEM. İzin ayarlanamazsa özel kayıt oluşturma başarısız olur. Mevcut dizinlerin izinleri de düzeltilir; sembolik bağlantı/junction kayıt hedefleri reddedilir. Yönetici, aynı kullanıcı, disk yedeği veya fiziksel erişime karşı şifreleme sağlanmaz. Uygulama JSON dışa aktarmada da ortak maskeleme ve özel dosya izinleri kullanır.

“Yerel verileri sil”, tarama çalışmıyorken onayla yalnız uygulamanın rapor/indeks/audit dosyalarını siler; kaynak dosyaları veya kullanıcı dışa aktarımlarını silmez. Adli kurtarılamaz silme iddiası yoktur. SQLite eski satırlar için `secure_delete` ve WAL checkpoint kullanır; depolama/yedek katmanları ayrıca değerlendirilmelidir.

## Ağ ve kayıt

Üretim uygulaması otomatik rapor yüklemez, e-posta/SMS göndermez; hesap, Supabase veya ödeme akışı yoktur. Fontlar/ikon/arka plan yereldir. Geliştirme araçları açıkça çalıştırıldığında sabit örnek kaynaklarından indirme yapar; CI ve paket kurulumu da ağ kullanır. Bunlar oyuncu tarama telemetrisi değildir.

`audit.json` yalnız zaman, olay türü ve sayı tutar: tarama başlangıcı/bitişi, kısmi/durdurulmuş tarama ve rapor dışa aktarma. Yol, komut, e-posta veya rapor içeriği yazılmaz. Bu yerel günlük bütünlük korumalı değildir; dosyaya izinsiz erişimi veya tüm sızıntıları otomatik algılamaz. Olay müdahale adımları: [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md).

0.3.8: Kalıcı indekste tespit sonucu/temiz sonucu önbelleği tutulmaz; eski cache alanları temizlenir. İmzalı olmayan SHA-256 içerik makbuzu kişisel veri alanı eklemez; bunun amacı bağımsız saklanan özgün özetle karşılaştırmadır. Makbuz bulunan eski raporlar otomatik yeniden mühürlenmez; içerik değişmişse okuyucu özeti reddeder. Yerel dosya sahibi veya yönetici, uygulama kodunu ve rapor/özet çiftini değiştirebilir. Ayrıntılar: [LOCAL-INTEGRITY.md](LOCAL-INTEGRITY.md).

## Sunucu tarafından bildirilen reddetme kuralı

Kullanıcının talimatıyla teknik bilgilendirmede ayrı bir sunucu kontrol kuralı gösterilir: hile kontrolünde talep edilen kontrol uygulamasını kullanmayı reddetmenin sunucu yönetimi tarafından 30 gün uzaklaştırma ile yaptırıma bağlandığı bildirilir. Reddetme/Vazgeç seçeneği korunur; AtlasAC reddetmeyi dışarıya göndermez, otomatik ban vermez ve bu durumu hile kanıtı saymaz. Bu metin kuralın hukuken geçerli olduğuna ilişkin değerlendirme veya genel sorumluluk muafiyeti değildir. Veri sorumlusunun yükümlülüklerini kaldırdığı iddia edilmez.

KVKK'nın resmî yayınlarında açık rızanın özgür iradeyle verilmesi gerektiği; hizmetten yararlanmanın açık rıza şartına bağlanmasının özgür irade unsurunu zedeleyebileceği belirtilir. 30 günlük yaptırım altında alınan onayın ve kuruluşun işleme şartının somut durumda değerlendirilmesi gerekir; yalnız “reddetmekte serbest” yazılması geçerli açık rızayı garanti etmez. Bu inceleme tamamlanmış sayılmaz.

Kaynaklar: [KVKK — 2025/1072 İlke Kararı](https://www.kvkk.gov.tr/Icerik/8338/2025-1072), [KVKK — 100 Soruda KVKK](https://kvkk.gov.tr/SharedFolderServer/CMSFiles/185c2130-8070-4b2b-a91e-1d48322ca352.pdf).
