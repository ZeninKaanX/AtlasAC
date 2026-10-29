Ghost client dosya tespiti Hydrogen, Nemui (Weave/Forge), VOX, Lumina, Zyklon, Fusion+ DLL ve Linux Wraith ile genişletildi. Yeni 13 gerçek dosya yedi adlandırılmış projeyi kapsar; türevler ayrı bağımsız mimari olarak sayılmaz.

Java istemcilerde üç özgül sınıf birlikte aranır; normal Hydrogen/ImmediatelyFast gibi isim benzerliği olan performans modları bu isimlerle hile sayılmaz. Fusion+/Wraith için yalnızca doğrulanan tam SHA-256/boyut eşleşir. `.AppImage` aday uzantılarına eklendi. Zyklon'un ZIP içindeki gerçek payload'ı ve çıkarılmış hali kontrol edildi; generic injector tek başına hile sayılmaz. Nemui ve Lumina'nın gerçek ikonları eklendi (toplam 20).

Linux'ta tam örnek kümesiyle 66 kontrol: 20 pozitif dosya, dört normal dağıtım ve üç normal EXE için kontroller, ad değiştirme, metadata kaldırma, iç paket ve canlı/önbellek sonuçları. İki Hydrogen ghost sürümünde bozuk metadata hatası gizlenmez: sınıf tespiti görünürken sonuç kısmi kalır. Windows/Ubuntu CI, yeniden indirilebilen kümede 60 gerçek örnek kontrolü çalıştırır. Hileler çalıştırılmadı.

Bütün ghost client'lar veya bellekteki/silinmiş enjeksiyonlar için garanti yoktur. Vape, Whiteout, Entropy, Dream, Drip, Slinky ve Raven için doğrulanmış özel kural eklenmedi. CPU bütçesi ve 590 saniye sınırı korunur. Ayrıntılar kaynak depodaki docs/GHOST-COVERAGE.md dosyasındadır.
