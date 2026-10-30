"""Local consistency controls, not remote attestation or a digital signature."""
import hashlib,hmac,json,os
from pathlib import Path

OFFICIAL_RULES_SHA256='0af450f9a45f066997ab9579fe31ceafba9d1a18e65de4aefc56b74a138dabc2'


def canonical(value):
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def rules_digest(rules):return hashlib.sha256(canonical(rules)).hexdigest()


def rules_match(rules):return hmac.compare_digest(rules_digest(rules),OFFICIAL_RULES_SHA256)


def require_official_rules(rules):
    if not rules_match(rules):raise ValueError('Kural bütünlüğü doğrulanamadı. Bu kurallarla standart AtlasAC taraması başlatılamaz.')


def integrity_state(rules):
    return {'rules_sha256':rules_digest(rules),'bundled_rules_match':rules_match(rules),
            'persistent_result_cache':'disabled','protocol_consistent':True,
            'independent_verification':False,'digital_signature':False,
            'note':'Yerel tutarlılık kontrolü; oyuncunun yönettiği bilgisayarı veya çalışan kodu bağımsız doğrulamaz.'}


def mark_failure(report,reason):
    report['status']='partial'
    report.setdefault('integrity',{})['protocol_consistent']=False
    report.setdefault('issues',[]).append({'path':'Sonuç bütünlüğü','reason':reason})
    report['issues_total']=max(report.get('issues_total',0),len(report['issues']))
    return report


def finding_id(row):
    return canonical({k:row.get(k) for k in ('rule','path','method','evidence')})


def validate_file_progress(data,snapshot):
    keys=('files_seen','discovered_candidates','directories_seen','processed_candidates')
    for key in keys:
        if key in data or key in snapshot:
            value=data.get(key)
            if type(value) is not int or value<snapshot.get(key,0):raise ValueError('Dosya ilerleme sayacı geriledi veya geçersiz: '+key)
    if 'discovery_complete' not in data and 'discovery_complete' not in snapshot:return
    complete=data.get('discovery_complete')
    if type(complete) is not bool or snapshot.get('discovery_complete') and not complete:raise ValueError('Dosya listesi durumu geçersiz.')
    done=data.get('processed_candidates',0);found=data.get('discovered_candidates',0)
    if done>found:raise ValueError('İşlenen aday sayısı keşfedilen aday sayısını aşıyor.')
    total=data.get('total_candidates');percent=data.get('progress_percent')
    if complete:
        if type(total) is not int or total!=found:raise ValueError('Toplam aday sayısı dosya listesiyle uyuşmuyor.')
        if snapshot.get('discovery_complete') and total!=snapshot.get('total_candidates'):raise ValueError('Tamamlanan dosya listesinin toplamı değişti.')
        expected=100. if not total else round(100.*done/total,1)
        if type(percent) not in (int,float) or abs(percent-expected)>.11:raise ValueError('Dosya yüzdesi sayaçlarla uyuşmuyor.')
    elif total is not None or percent is not None:raise ValueError('Dosya listesi tamamlanmadan kesin yüzde bildirildi.')
    eta=data.get('eta_seconds')
    if eta is not None and (type(eta) not in (int,float) or eta<0):raise ValueError('Kalan süre tahmini geçersiz.')


def checked_final(snapshot,final,rules,roots):
    """Never permit a final packet to erase already observed evidence or shrink scope."""
    if not isinstance(final,dict):return mark_failure(snapshot,'Final rapor biçimi geçersiz.')
    canonical(final)  # Reject non-JSON objects / non-finite numbers before touching retained data.
    required={'findings':list,'files':list,'issues':list,'artifacts':dict,'components':list}
    if any(not isinstance(final.get(k),t) for k,t in required.items()):return mark_failure(snapshot,'Final rapor alanları eksik veya geçersiz.')
    if any(not isinstance(r,dict) for k in ('findings','files','issues','components') for r in final[k]):return mark_failure(snapshot,'Final kayıt biçimi geçersiz.')
    if final.get('status') not in ('completed','partial','cancelled'):return mark_failure(snapshot,'Final tarama durumu geçersiz.')
    reasons=[]
    try:validate_file_progress(final,snapshot)
    except ValueError as exc:reasons.append(str(exc))
    if final.get('application')!='AtlasAC' or final.get('version')!=snapshot.get('version') or final.get('rule_version')!=rules.get('version'):reasons.append('Uygulama / kural sürümü uyuşmuyor.')
    expected=[os.path.normcase(str(Path(r).resolve())) for r in roots]
    observed=final.get('roots',[])
    if not isinstance(observed,list) or observed!=list(map(str,observed)) or [os.path.normcase(r) for r in observed]!=expected:reasons.append('Tarama kökleri değişmiş veya eksik.')
    for key in ('indexed_files','content_files','ignored_files','issues_total'):
        value=final.get(key)
        if type(value) is not int or value<snapshot.get(key,0):reasons.append('Tarama sayacı geriledi veya geçersiz: '+key)
    known={finding_id(row):row for row in snapshot['findings']};seen={finding_id(row) for row in final['findings']}
    if known.keys()-seen:
        final['findings'].extend(known[k] for k in known.keys()-seen);reasons.append('Canlı eşleşmeler final raporundan çıkarılmış.')
    prior=snapshot.get('artifacts',{}).get('review_signals',[])
    present=final['artifacts'].get('review_signals',[])
    if not isinstance(present,list):present=[];reasons.append('İnceleme kayıtları geçersiz.')
    identities={canonical(row) for row in present}
    missing=[row for row in prior if canonical(row) not in identities]
    if missing:final['artifacts']['review_signals']=present+missing;reasons.append('Canlı inceleme kayıtları final raporundan çıkarılmış.')
    components={canonical(row) for row in final['components']}
    missing_components=[row for row in snapshot.get('components',[]) if canonical(row) not in components]
    if missing_components:final['components'].extend(missing_components);reasons.append('Canlı kapsam kayıtları final raporundan çıkarılmış.')
    if final['status']=='completed' and (final['issues'] or final.get('issues_total') or any(c.get('status') in ('partial','unavailable','error') for c in final['components'])):reasons.append('Eksik kapsam tamamlanmış olarak bildirilmiş.')
    final['integrity']=integrity_state(rules)
    for reason in reasons:mark_failure(final,reason)
    return final


def validate_progress(data,snapshot):
    try:canonical(data)
    except (TypeError,ValueError) as exc:raise ValueError('Canlı mesaj JSON verisi geçersiz.') from exc
    validate_file_progress(data,snapshot)
    for key in ('phase','path'):
        if not isinstance(data.get(key),str):raise ValueError('Canlı tarama metni geçersiz.')
    for key in ('indexed','matches'):
        if type(data.get(key)) is not int or data[key]<0:raise ValueError('Canlı tarama sayacı geçersiz.')
    if data['indexed']<snapshot.get('indexed_files',0):raise ValueError('Canlı dosya sayacı geriledi.')
    for key in ('new_findings','recent_files','components'):
        rows=data.get(key,[])
        if not isinstance(rows,list) or not all(isinstance(r,dict) for r in rows):raise ValueError('Canlı kayıt biçimi geçersiz: '+key)
    if data['matches']!=len(snapshot['findings'])+len(data.get('new_findings',[])):raise ValueError('Canlı eşleşme sayacı kayıtlarla uyuşmuyor.')
    for key in ('artifact_snapshot','artifact_delta'):
        values=data.get(key,{})
        if not isinstance(values,dict) or any(not isinstance(rows,list) or not all(isinstance(r,dict) for r in rows) for rows in values.values()):raise ValueError('Canlı sistem kaydı biçimi geçersiz.')
    for key in ('content_files','ignored_files','cache_hits','archive_reuses','issues_total'):
        if key in data and (type(data[key]) is not int or data[key]<snapshot.get(key,0)):raise ValueError('Canlı kapsam sayacı geriledi: '+key)


class SessionMessages:
    """Bind worker messages to this parent's session; this is not a host trust boundary."""
    def __init__(self,queue,session):self.queue=queue;self.session=session;self.sequence=0
    def put(self,item):
        self.sequence+=1
        kind,data=item
        self.queue.put({'session':self.session,'sequence':self.sequence,'kind':kind,'data':data})


def validate_packet(packet,session,expected_sequence):
    if not isinstance(packet,dict) or packet.get('session')!=session or type(packet.get('sequence')) is not int or packet['sequence']!=expected_sequence:
        raise ValueError('Tarama oturumu / mesaj sırası doğrulanamadı.')
    if packet.get('kind') not in ('progress','ready','error'):raise ValueError('Bilinmeyen tarama mesajı.')
    if packet['kind']!='error' and not isinstance(packet.get('data'),dict):raise ValueError('Tarama mesajı biçimi geçersiz.')
    if packet['kind']=='error' and not isinstance(packet.get('data'),str):raise ValueError('Tarama hata mesajı geçersiz.')
    return packet['kind'],packet.get('data')


def receipt_digest(report):
    value={k:v for k,v in report.items() if k!='report_receipt'}
    return hashlib.sha256(canonical(value)).hexdigest()


def attach_receipt(report):
    from .privacy import minimize_report
    value=minimize_report(report)
    value['report_receipt']={'algorithm':'SHA-256','payload_sha256':receipt_digest(value),
                             'signed':False,'note':'İmza değildir. Bağımsız saklanan özgün özetle karşılaştırılmadıkça kaynağı doğrulamaz.'}
    return value


def verify_receipt(report,expected=None):
    receipt=report.get('report_receipt',{})
    digest=receipt_digest(report)
    supplied=receipt.get('payload_sha256') if isinstance(receipt,dict) else None
    matches=isinstance(receipt,dict) and receipt.get('algorithm')=='SHA-256' and isinstance(supplied,str) and len(supplied)==64 and all(c in '0123456789abcdef' for c in supplied) and hmac.compare_digest(digest,supplied)
    if expected is not None:
        if not isinstance(expected,str) or len(expected)!=64 or any(c not in '0123456789abcdefABCDEF' for c in expected):raise ValueError('Beklenen özet 64 haneli SHA-256 olmalı.')
        matches=matches and hmac.compare_digest(digest,expected.lower())
    return {'checksum_matches':bool(matches),'compared_with_external_digest':expected is not None,
            'digital_signature':False,'host_verified':False,'payload_sha256':digest,
            'note':'SHA-256 içerik karşılaştırmasıdır; hile taramasının gerçekliğini veya oyuncu bilgisayarını doğrulamaz. Oyuncunun raporla birlikte gönderdiği yeni özet bağımsız kanıt değildir.'}
