# Ocean ve AtlasOyuncu incelemesi — 29 Ekim 2026

Ocean’ın kullanıcı tarafından açık bırakılan paneli ve kendi laboratuvarımızdaki bir taramanın sonucu incelendi. Özel kaynak kodu veya tespit motoru elde edilmedi. Benzer sonuç düzeni aynı tespit kapasitesi anlamına gelmez. Kullanıcının son talebine göre AtlasAC 0.2’de hesap/PIN/key/oyuncuya özel indirme akışı tamamen kaldırıldı; yerel Qt masaüstü arayüzüne geçildi.

## Uygulamalı Ocean testi

Kullanıcının QEMU Windows 11 Enterprise LTSC laboratuvarı kullanıldı. Görev referansı için bu oturumda `read_thread` aracı sunulmadığından görev bağlantısı araç üzerinden okunamadı; aynı görevin yerel kayıtları ve VM belgeleri yardımcı bağlam olarak incelendi. Parola/oturum bilgileri projeye eklenmedi.

Resmi [Ocean indirme akışı](https://anticheat.ac/) üzerinden alınan x64 PE dosyası: 56.093.696 bayt, SHA-256 `d5a644614a1de55b30d8031a5fde0a2c0895d5d0dacbacd765d5e03d65329adb`. Defender başlangıçta `Trojan:Win32/Ulthar.A!ml` etiketiyle karantinaya aldı; başka denemede Sabisk.FL.A!ml bildirimi görüldü. Etiketler dosyanın gerçekten zararlı veya kesin yanlış pozitif olduğuna bağımsız hüküm vermez.

Kullanıcının açık talebi üzerine yalnız VM’de Defender gerçek zamanlı koruması geçici kapatıldı. Ocean yeniden indirildi, UAC ve koşullar kabul edildi ve tarama tamamlandı. Sonuç: **2m48s; 46 log; 2 tespit; 2 uyarı; %44 panel riski**. Tespitler CURL ile dosya indirme/değiştirme ve laboratuvardaki UPX paketli BrowsingHistoryView dosyasıydı. Memory Integrity ve Fast Boot uyarıları ayrıca listelendi. Oyun açık değildi; altı hazırlanmış mod tespit listesinde görünmedi. Farklı lisans veya oyun koşullarında başarı hakkında genelleme yapılamaz. CURL/UPX bulgusunu tek başına hile saymak uygun değildir.

Testten sonra Defender gerçek zamanlı koruması **On** durumuna getirildi ve ekran görüntüsüyle doğrulandı. Host güvenlik ayarları değiştirilmedi. AtlasAC’nin kendisi güvenlik korumalarını değiştirmez. Eski denemelere ait indirme/Python/antivirüs izleri laboratuvar etkinliğidir; oyuncunun hile kullandığını göstermez.

Ocean panelinde PIN oluşturma, tarama bekleme, büyük risk/özet alanı, tespit/uyarı filtreleri ve satır ayrıntıları incelendi. AtlasAC’de gerekli düzen yerel sonuç sekmelerine aktarıldı; web hesabı veya özel motor varmış gibi gösterilmez. Özel oyuncu raporları, kimlik bilgileri veya çerezler dağıtıma eklenmedi.

## AtlasOyuncu görsel kimliği

[Resmi site](https://atlasoyuncu.com/) tarayıcıda ve kaynak varlıklarıyla incelendi. Sitenin **kendi logosu ve hareketli deniz/Minecraft arka planı değiştirilmeden** kullanıldı. Poppins yazı ailesi, koyu saydam paneller, mavi düğmeler ve turkuaz vurgular yerel Qt bileşenlerine aktarıldı. Görsellerin kaynakları ve SHA-256 değerleri [BRAND-ASSETS.json](BRAND-ASSETS.json) dosyasındadır. Ocean logosu kullanılmaz.

## Kanıt kaynakları ve sınırlar

[Ocean Minecraft tespit belgeleri](https://anticheat.ac/docs/detections/detects-logs/minecraft) bellek, hook ve JVM/JVMTI kaynakları anlatır; [sürüm notları](https://anticheat.ac/changelog) yanlış pozitif ve mod analizi düzeltmeleri içerir. Bunlar ürünün kendi beyanlarıdır. AtlasAC bu motorların eşdeğerini uyguladığını iddia etmez.

| Alan | AtlasAC 0.2 |
|---|---|
| Bilinen mod kimlikleri / sınıf adları / yerel SHA-256 | Mevcut |
| Uzantı değişikliği / ZIP eklenmiş görüntü / iç arşiv | Mevcut; bütçe ve derinlik sınırı var |
| Belirli sohbetten konsola Java backdoor deseni | Dört gerçek dosyada tek desen doğrulandı |
| Genel Trojan / RAT / stealer / bilinmeyen obfuscation | Yok |
| Oyun belleği / native ghost client / Java agent / JVMTI | Yok |
| Aim, reach, KillAura, velocity, timer, fly, speed, scaffold davranışı | Yok |
| Genel Xray / ESP / kaynak paketi davranışı | Yok; yalnız eşleşen istemci dosyası izi |
| Autoclicker / makro / harici giriş cihazı davranışı | Yok |
| USN, BAM, Prefetch, Amcache, silinmiş dosyalar | Yok |
| DMA / çekirdek / firmware | Yok |

[Grim’in birincil deposu](https://github.com/GrimAnticheat/Grim) sunucu hareket tahmini ve gecikme telafisini; [Paper Anti-Xray belgesi](https://docs.papermc.io/paper/anti-xray/) gönderilen dünya bilgisini sınırlamayı açıklar. Bu yaklaşımlar yerel dosya kontrolünden ayrı işlerdir.

Kuralların biçim kaynakları: [Fabric metadata](https://docs.fabricmc.net/develop/loader/fabric-mod-json), [NeoForge metadata](https://docs.neoforged.net/docs/1.20.6/gettingstarted/modfiles/), [JVM sınıf dosyası sabit havuzu](https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html). Gerçek örneklerin resmi release/Modrinth URL’leri manifest ve ölçüm raporlarında bulunur. Backdoor karşı örnekleri [MCHCC arşivi](https://mchccbackup.github.io/downloadc.html) kaynaklıdır ve dağıtıma dahil edilmez.

## 0.2.1 kapsam genişletmesi

Resmi sürüm dosyalarında ForgeHax, Seppuku, Aoba, Cigarette, Ares, NightX, CrossSine, Krs, LiveOverflowMod ve Combatant için ek kurallar geliştirildi. İlk incelenen dosyalar ile sonraki doğrulama sürümleri ayrıldı. LiquidBounce+ Reborn, metadata ve sınıf alanı ana projeyle aynı olduğundan ayrı bir istemci motoru gibi etiketlenmedi; `liquidbounce` grubunda tutuldu. NightX/CrossSine/FDP gibi türevler adlandırılmış gruplardır; bunların ayrı, bağımsız mimariler olduğu iddia edilmez.

Cigarette için genel yazar paket adı yerine iki tam sınıf adının birlikte bulunması kullanıldı. CrossSine metadata ile tanındığında, paylaşılan sınıf alanı nedeniyle ikinci bir LiquidBounce bulgusu üretilmez. ViaVersion/ViaBackwards, Mixin, Nashorn veya JNA gibi paketlenmiş normal kütüphaneler tek başına hile sayılmaz.

Birincil kaynaklar: [ForgeHax](https://github.com/fr1kin/ForgeHax), [Seppuku](https://github.com/seppukudevelopment/seppuku), [Aoba resmi indirmeleri](https://www.aobaclient.com/download), [Cigarette resmi sitesi](https://cigarette.dev/), [Ares resmi indirmeleri](https://aresclient.org/download), [NightX](https://github.com/Aspw-w/NightX-Client), [CrossSine](https://github.com/shxp3/CrossSine), [Krs](https://github.com/Aspw-w/Krs), [LiveOverflowMod](https://github.com/JorianWoltjer/LiveOverflowMod), [Combatant](https://github.com/pivosos2007/combatant-client), [LiquidBounce+ Reborn](https://github.com/liquidbounceplusreborn/LiquidbouncePlus-Reborn). Dosya URL/hash/rol bilgileri `corpus/combined-candidates.json` ve ölçüm raporlarında saklanır.
