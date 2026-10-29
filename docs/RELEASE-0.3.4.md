# AtlasAC 0.3.4

Windows ve Linux için AtlasOyuncu temalı yerel masaüstü inceleme aracı. Hesap, key, kurulum sihirbazı veya web arayüzü gerekmez.

- Dosyalar ve şüpheli eşleşmeler tarama sırasında canlı gösterilir.
- PowerShell/CMD/kabuk komut izleri ve iz silme belirtileri incelenir; kayıt eksikleri belirtilir.
- DoomsDay'in resmi normal ve rastgele boyutlu iki loader örneği, birlikte aranan iki iç sınıf SHA-256 değeriyle doğrulandı. Bu, tüm sürümler veya bütün ghost istemcileri için garanti değildir.
- Ortak tarayıcı CPU bütçesi, iyileştirilmiş JAR eşleştirmeleri ve küçültülmüş pencerede duran animasyonlar bulunur.
- Sesli sonuç animasyonu Sonuçlar düğmesine basılana kadar açık kalır. Şeffaf Atlas logosu, Minecraft balıkları ve 18 istemci ikonu kullanılır.

Doğrulama: Linux 58 test başarılı; Windows 57 test başarılı, bir yetki testi atlandı. Ayrıntılar `docs/VALIDATION.md` dosyasında.

Windows için `AtlasAC.exe`, Linux için `AtlasAC-Linux-x64` dosyasını indirin. Linux'ta gerekirse çalıştırma izni verin. `SHA256SUMS.txt` indirmelerin SHA-256 değerlerini içerir. ZIP/TAR paketleri aynı uygulamaları içerir.

Paketler imzasızdır. Linux paketi glibc 2.44 üzerinde üretildi; eski dağıtımlarda doğrulanmadı. Eşleşme, aktif hile kullanımının kanıtı değildir. Silinmiş dosyalar, yalnız bellekte kalan enjeksiyonlar ve hiç kaydedilmemiş komutlar için tam tespit/kurtarma garantisi verilmez. Normal tarama 590 saniye ile sınırlıdır; tamamlanmayan kapsam kısmi gösterilir. Sonuç ekranındaki bekleme bu süreye dahil değildir.
