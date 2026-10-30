# AtlasAC 0.3.8 — yerel sonuç bütünlüğü

Kullanıcı bu aşamada **yalnız yerel korumaları** seçti. Sunucu, hesap, key veya otomatik rapor gönderimi eklenmedi. OceanAC'nin özel bypass yöntemleri test edilmedi; aşağıdaki kontroller AtlasAC'nin kendi veri yollarında doğrulandı.

## Uygulanan sınırlar

1. **Kalıcı tespit önbelleğine güvenilmez.** SQLite cache alanı okunarak dosya atlanmaz; önceki cache verileri temizlenir ve yeni tespit sonucu yazılmaz. `probe(cached=...)` da dışarıdan verilmiş hazır sonuca güvenmez. Her oturumda erişilen aday dosyalar yeniden açılır/incelenir. Aynı oturum içinde taze SHA-256 ile okunan birebir arşivler sınırlı RAM önbelleğini paylaşabilir; dosya yolları korunur. CPU bütçesi değişmedi; kalıcı önbelleğin kaldırılması sonraki taramaları yavaşlatabilir ve 590 saniye içinde ulaşılan kapsamı azaltabilir.
2. **Standart GUI/CLI kural özeti kontrol edilir.** Dağıtımdaki kuralların canonical JSON SHA-256 özeti kodda sabittir. Satır sonu/boşluk farkı kabul edilir; anlamı değişen kurallar ve yinelenen JSON anahtarları reddedilir. GUI başlangıçta yüklediği kuralları ve tarama öncesi diskteki standart kuralları denetler. Geliştirme kütüphaneleri test fixture kuralları kabul edebilir; rapor bunları standart kurallarla eşleşmiş göstermez. Bu kontrol, çalışan Python/native kodun değiştirilmesini engelleyen bir imza değildir.
3. **Tarama mesajları oturum ve sıra taşır.** Her alt süreç için ebeveynde rastgele oturum oluşturulur; yanlış oturum, sıra boşluğu ve geçersiz mesaj reddedilir. Sayaçlar gerileyemez; eşleşme sayacı canlı kayıt sayısıyla uyuşmalıdır. Bozuk kayıtlar eldeki sonuçları sıfırlamak yerine kısmi sonuç üretir. Bu mekanizma çalışan sürece tam erişebilen saldırgana karşı kimlik doğrulama değildir.
4. **Final paket önceki kanıtı silemez.** Canlı eşleşme veya inceleme/kapsam kaydı finalden çıkarılırsa korunur ve bütünlük hatası eklenir. Uygulama/kural sürümü, kökler ve sayaçlar karşılaştırılır. Eksik kapsamı “tamamlandı” diye bildiren final kısmiye çevrilir. Hata hile kullanımı kanıtı sayılmaz; eşleşmesiz sonuç “Temiz” olamaz.
5. **Rapor içerik makbuzu.** Minimize edilen raporun canonical içeriğine SHA-256 eklenir; `report_receipt` alanı hash kapsamından çıkarılır. Yerel geçmiş okuyucusu makbuzu olmayan veya makbuzla uyuşmayan raporu reddeder ve geçmiş bakımı bu raporu yeniden mühürlemez. Standart GUI JSON dışa aktarmada içerik özetini gösterir.

## Özgün raporla karşılaştırma

Denetleyen kişi özgün tarama sırasında özeti **oyuncunun sonradan değiştiremeyeceği ayrı bir ortamda** saklamalıdır. Güvenilen bilgisayarda resmî uygulama ile:

```text
AtlasAC.exe --verify-report rapor.json --expected-digest AYRI_SAKLANAN_64_HANELI_OZET --output kontrol.json
```

Linux'ta `AtlasAC-Linux-x64` aynı parametreleri destekler. Beklenen özet belirtilmeden yapılan kontrol yalnız raporun kendi hash alanıyla tutarlı olup olmadığını gösterir; bağımsız doğrulama değildir. Dönüş kodları: eşleşme 0, eşleşmeme 2, okunamayan/geçersiz girdi 1.

**Makbuz dijital imza değildir.** Rapor ve özet aynı oyuncudan birlikte alınıyorsa ikisi de yeniden üretilebilir. Bu durum testte açıkça gösterilir: değiştirilmiş raporun yeni özeti kendi içinde eşleşir, denetleyenin ayrı sakladığı özgün özetle eşleşmez. Dosya uzantısını değiştirmek, ekran görüntüsünü düzenlemek veya başka bir uygulamayı AtlasAC gibi göstermek bu yöntemle engellenemez.

## Kalan güven sınırı

Bilgisayarı tam yöneten kullanıcı/yönetici; Python/native kodu yamalayabilir, işletim sistemi okumalarını kancalayabilir, dosyaları saklayabilir veya görünümü taklit edebilir. Yerel izinler aynı kullanıcı/yöneticiye karşı kriptografik koruma sağlamaz. Kodda gömülü gizli bir imza/HMAC anahtarı bu sorunu çözmez; bu nedenle böyle bir güven iddiası eklenmedi. Bağımsız sunucu doğrulaması, donanım/işletim sistemi güven kökü, güvenilen denetleyen cihaz ve kod imzalama bu sürümün kapsamı dışındadır. Tüm hilelerin/bypassların engellendiği söylenemez.

0.3.7 ve öncesindeki makbuzsuz raporlar yeni okuyucuda doğrulanmış sonuç olarak açılmaz; dosyalar otomatik silinmez. Makbuz alanını kaldırmak doğrulamayı atlatmaz. Mevcut geçersiz makbuzla verilen rapor geçmişe yeniden mühürlenerek yazılmaz.
