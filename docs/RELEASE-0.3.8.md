AtlasAC 0.3.8, yerel sonuç manipülasyonuna karşı tutarlılık kontrolleri ekler.

- Diskteki hazır tespit/temiz önbelleğine güven kaldırıldı. Dosyalar her taramada yeniden incelenir; aynı oturumdaki taze hash ile doğrulanmış arşiv paylaşımı korunur.
- Standart GUI/CLI, dağıtımın kural özetiyle uyuşmayan kuralları reddeder. Yinelenen JSON anahtarları kabul edilmez.
- Tarama mesajlarında oturum/sıra/sayaç kontrolü; final raporda canlı eşleşme ve kapsam kayıtlarının korunması. Bozuk veya çelişkili sonuç kısmi kalır, eşleşmesizken Temiz olmaz.
- JSON içerik özeti ve bağımsız saklanmış özgün özetle karşılaştırma komutu eklendi. Bu özet dijital imza değildir; oyuncu rapor ve özeti birlikte yeniden üretebilir. Tam kontrol edilen bilgisayara karşı mutlak koruma iddiası yoktur.

Yalnız yerel korumalar eklendi; hesap, key veya sunucu gönderimi yoktur. CPU/590 saniye sınırı korunur; kalıcı tespit önbelleğinin kaldırılması sonraki taramaların süresini ve erişilen kapsamı etkileyebilir. Ayrıntılar: docs/LOCAL-INTEGRITY.md.

Doğrulama: Windows'ta 92 test, Linux'ta 91 test + bir Windows'a özel atlama; son Windows/Ubuntu CI'de 60'ar gerçek örnek kontrolü ve paket başına üç rapor değiştirme/karşılaştırma denemesi geçti. Yerel Linux tam örnek kümesinde 66 kontrol geçti; 0,1 çekirdek hedefiyle 60 kontrollük küçük örnek iş yükü tekrarlandı ve geçti. Önceki bir Ubuntu kontrolündeki ayrıntısı korunmamış başarısızlık da doğrulama belgesinde açıkça kaydedildi; test beklentileri gevşetilmedi. Ayrıntılar: docs/VALIDATION-0.3.8.md.
