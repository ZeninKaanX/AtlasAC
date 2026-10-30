Düşük CPU hedefinde sık zamanlayıcı uyanmalarının maliyeti CPU payını tüketip tarama okuyucularını ilerleyemez durumda bırakabiliyordu. Bekleme artık bir işleme payı biriktirir; iptal sinyali beklemeyi doğrudan uyandırır. CPU hedefi, arşiv başına 30 saniye ve toplam 590 saniyelik tarama sınırı artırılmadı. Bu durum eski kodda başarısız, düzeltmede başarılı olan bir regresyon testiyle gösterildi. Tek başına bu test, önceki uzak CI hatasının kök nedenini kesinleştirmez.

Tarama öncesinde 30 günlük kontrolü reddetme yaptırımı ayrı sunucu kuralı olarak gösterilir. Oyuncu Vazgeç diyebilir; AtlasAC otomatik ban vermez, reddetme bilgisini göndermez ve reddetmeyi hile kanıtı saymaz. Genel bir sorumluluktan muafiyet eklenmedi; yaptırım koşulunun açık rızaya etkisi ayrıca değerlendirilmelidir.

Kalıcı sonuç önbelleğine güvenilmemesi, yerel bütünlük kontrolleri, veri minimizasyonu ve mevcut tespit kuralları korunur. Sonuçlar dosya izini gösterir; tüm hileleri yakalama veya aktif kullanım garantisi değildir.

Doğrulama: [Windows / Ubuntu CI](https://github.com/ZeninKaanX/AtlasAC/actions/runs/41055401738) başarılı. Windows’ta 93 test; Linux’ta 92 test ve 1 Windows özel testi atlaması. Her platformda 60 gerçek dosya/statik varyant kontrolü, paket içeriğinin kaynakla karşılaştırması ve 3/3 rapor doğrulama denemesi geçti. Örnekler çalıştırılmadı. Ayrıntılar: [doğrulama kaydı](https://github.com/ZeninKaanX/AtlasAC/blob/v0.3.10/docs/VALIDATION-0.3.10.md).

Windows ve Linux tek dosya paketleri bu başarılı CI çalışmasından gelir. Linux paketi Ubuntu 24.04 / glibc 2.39 üzerinde üretildi; eski dağıtımlarda doğrulanmadı.
