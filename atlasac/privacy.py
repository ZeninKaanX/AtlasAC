"""Shared output minimisation. Redaction reduces exposure; it cannot recognise every secret."""
import re,base64
from urllib.parse import urlsplit,urlunsplit

MASK='[REDACTED]'
SECRET=r'(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|secret|client[_-]?secret|session(?:id)?|authorization|cookie)'
VALUE=r'''(?:"[^"\n]*"|'[^'\n]*'|[^\s;,]+)'''
URL=re.compile(r'https?://[^\s<>"\']+',re.I)

def safe_url(value):
    try:
        parts=urlsplit(str(value))
        if parts.scheme.lower() not in ('http','https'):return '[URL OMITTED]'
        host=parts.hostname or ''
        if ':' in host:host='['+host+']'
        if parts.port:host+=':'+str(parts.port)
        # Path remains useful for downloaded file identity. Credentials/query/fragment do not.
        return urlunsplit((parts.scheme,host,parts.path,'',''))
    except (ValueError,TypeError):return '[URL OMITTED]'


def redact_text(value,_depth=0):
    text=str(value)
    def encoded(match):
        if _depth>=2:return match.group(1)+MASK
        try:
            decoded=base64.b64decode(match.group(2),validate=True).decode('utf-16-le')
            cleaned=redact_text(decoded,_depth+1)
            return match.group(1)+base64.b64encode(cleaned.encode('utf-16-le')).decode('ascii')
        except (ValueError,UnicodeError):return match.group(1)+MASK
    text=re.sub(r'(?i)(-(?:encodedcommand|enc|e)\s+)["\']?([A-Za-z0-9+/=]{4,65536})',encoded,text)
    text=re.sub(r'(?i)(\b(?:Authorization\s*:\s*)?(?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]+',r'\1'+MASK,text)
    text=re.sub(r'(?i)(\bCookie\s*:\s*)[^\r\n"\']+',r'\1'+MASK,text)
    text=re.sub(r'(?i)((?:--?)?'+SECRET+r'''\b["']?\s*[=:]\s*)'''+VALUE,r'\1'+MASK,text)
    text=re.sub(r'(?i)((?:--?|/)'+SECRET+r'\b\s+)'+VALUE,r'\1'+MASK,text)
    return URL.sub(lambda m:safe_url(m.group()),text)


def safe_argv(args):
    result=[];hide=False;encoded_flag=None
    for arg in args or []:
        if not isinstance(arg,str):continue
        if hide:result.append(MASK)
        elif encoded_flag:result.append(redact_text(encoded_flag+' '+arg).split(' ',1)[-1])
        else:result.append(redact_text(arg))
        hide=bool(re.fullmatch(r'(?i)(?:--?|/)'+SECRET,arg))
        encoded_flag=arg if re.fullmatch(r'(?i)-(?:encodedcommand|enc|e)',arg) else None
    return result


def sanitize(value,key=''):
    if isinstance(value,dict):
        return {k:(MASK if re.fullmatch(SECRET,str(k),re.I) else safe_argv(v) if k=='cmdline' and isinstance(v,list) else sanitize(v,str(k))) for k,v in value.items()}
    if isinstance(value,list):return [sanitize(v,key) for v in value]
    if isinstance(value,tuple):return [sanitize(v,key) for v in value]
    if isinstance(value,str):return redact_text(value)
    return value

RETENTION_DAYS=7
REPORT_LIMIT=50
CONTROLLER='TrueFormTech'
CONTACT='trueformtechx@gmail.com'
NOTICE_VERSION='2026-10-30.2'
SERVER_CONTROL_POLICY='Sunucu yönetiminin bildirdiği kontrol kuralına göre, hile kontrolü kapsamında talep edilen bir kontrol uygulamasını kullanmayı reddeden oyuncuya 30 gün sunucudan uzaklaştırma (ban) uygulanır. Oyuncu reddedebilir; yaptırım kararı ve uygulaması sunucu yönetimine aittir. AtlasAC otomatik ban uygulamaz.'


def minimize_report(report):
    result=sanitize(report)
    artifacts=result.get('artifacts',{})
    artifacts.pop('history',None)  # Previous releases saved general browsing history.
    for row in artifacts.get('processes',[]):row.pop('username',None)
    for key in ('usb','connected_usb'):
        for row in artifacts.get(key,[]):
            for field in tuple(row):
                if field.lower() in ('serial','serialnumber','instance','containerid','pnpdeviceid'):row.pop(field,None)
    return result


def notice_text():
    return f'''Tarama öncesi bilgilendirme
Sorumlu olarak belirtilen kuruluş: {CONTROLLER}
İletişim / veri talepleri: {CONTACT}
Sürüm: {NOTICE_VERSION}

Sunucu kontrol kuralı — KVKK aydınlatması ve açık rızadan ayrı
{SERVER_CONTROL_POLICY}
Bu kural tek başına geçerli açık rıza oluşturmaz ve veri sorumlusunun kanuni yükümlülüklerini ortadan kaldırmaz.

Amaç: Kullanıcının başlattığı yerel oyun dosyası ve sistem izi incelemesi. Eşleşme, oyunda hile kullanımı veya ceza kanıtı değildir.

Kapsam: Yerel disklerde aday dosya yolları, boyut/zaman/hash, bilinen kural eşleşmeleri; erişilebilen işlem ve seçili modül yolları, maskelenmiş komut kayıtları, başlangıç, USB, olay ve Windows etkinlik kayıtları. Yalnız bu oturumun tarayıcı profillerindeki ilgili indirmeler alınır; genel gezinme geçmişi kaydedilmez. Korunan alanlara erişilemeyebilir.

Gizlilik: Hesap/ödeme gerekmez; AtlasAC otomatik rapor göndermez. Çerez/parola kasası okunmaz. Komutlar ve URL'lerde bilinen sır biçimleri maskelenir; tüm sırların tanınması garanti edilemez. Sonuçları paylaşmadan önce kontrol et. JSON dışa aktarma kullanıcı isteğiyle yapılır; paylaşım ve kopyalarının silinmesi ayrıca yönetilmelidir.

Saklama: Raporlar ve dosya indeksi bu cihazda tutulur. En fazla {REPORT_LIMIT} rapor, {RETENTION_DAYS} gün; süre kontrolü uygulama açıldığında veya tarama başladığında yapılır. Uygulama kapalıyken otomatik görev çalışmaz. Sonuçlar sayfasından yerel rapor/indeks verilerini silebilirsin. Bu silme dışa aktarılan kopyaları kapsamaz ve adli kurtarılamaz silme değildir.

Kontrol senin elinde: Taramayı reddedebilir veya durdurabilirsin. Bu teknik bilgilendirme, kuruluşun hukuki işleme şartı ve diğer yükümlülüklerini belirlediği kapsamlı aydınlatma metni yerine geçmez. Sorular ve talepler için yukarıdaki iletişim adresini kullan.'''
