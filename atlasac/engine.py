"""Read-only scanner. Findings describe files, never prove in-game use."""
from __future__ import annotations
from bisect import bisect_left
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import threading
import time
import tomllib
import zipfile
import zlib
from datetime import datetime, timezone
from .classfile import references, known_chat_backdoor

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_ENTRIES = 30000
MAX_MEMBER = 2 * 1024 * 1024
MAX_NESTED = 256 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_SECONDS = 30
MAX_FILES = 10000
MAX_SECONDS = 120


def now():
    return datetime.now(timezone.utc).isoformat()


def load_rules(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(data.get('rules'), list) or not isinstance(data.get('hashes'), dict):
        raise ValueError('Kural dosyası geçersiz.')
    for rule in data['rules']:
        if not all(isinstance(rule.get(k), str) for k in ('id', 'name', 'category', 'source')):
            raise ValueError('Kural alanları geçersiz.')
        for key in ('mod_ids', 'class_prefixes', 'required_classes'):
            if key == 'required_classes' and key not in rule:
                continue
            if not isinstance(rule.get(key), list) or not all(isinstance(x, str) and x for x in rule[key]):
                raise ValueError('Kural eşleşmeleri geçersiz.')
        if 'required_classes' in rule and (len(set(rule['required_classes'])) < 2 or any(not x.endswith('.class') for x in rule['required_classes'])):
            raise ValueError('Sınıf imzası en az iki farklı .class gerektirir.')
    for rule in data['rules']:
        signatures = rule.get('file_signatures', [])
        if not isinstance(signatures, list) or any(
            not isinstance(s, dict) or type(s.get('size')) is not int or not 0 < s['size'] <= MAX_FILE
            or not isinstance(s.get('sha256'), str) or len(s['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in s['sha256']) for s in signatures
        ):
            raise ValueError('Dosya boyutu / SHA-256 imzası geçersiz.')
        if 'embedded_icon' in rule and type(rule['embedded_icon']) is not bool:
            raise ValueError('Gömülü ikon seçimi geçersiz.')
        members=rule.get('required_member_sha256',{})
        if not isinstance(members,dict) or (members and len(members)<2):raise ValueError('En az iki arşiv üyesi SHA-256 imzası gerekli.')
        if any(not isinstance(name,str) or not name.endswith('.class') or not isinstance(sha,str) or len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha) for name,sha in members.items()):raise ValueError('Arşiv üyesi SHA-256 imzası geçersiz.')
    for digest, label in data['hashes'].items():
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest) or not isinstance(label, str):
            raise ValueError('SHA-256 kuralı geçersiz.')
    return data


def match_file_signatures(rules, digest, size, label):
    """Exact published file identity; filenames and printable brand strings never trigger."""
    return [{
        'rule': rule['id'], 'name': rule['name'], 'category': rule['category'],
        'severity': 'high', 'path': label, 'method': 'file-sha256',
        'evidence': [digest, f'size:{size}'], 'source': rule['source'],
        'note': 'Doğrulanan dosyanın tam SHA-256 ve boyut eşleşmesi. Çalıştırıldığını veya oyuna enjekte edildiğini kanıtlamaz.'
    } for rule in rules['rules'] if any(
        s['size'] == size and s['sha256'] == digest for s in rule.get('file_signatures', [])
    )]


def inspect_archive(stream, label, rules, findings, issues, depth=0, budget=None):
    budget = budget if budget is not None else {'members': 0, 'bytes': 0, 'deadline': time.monotonic() + MAX_ARCHIVE_SECONDS}
    def checkpoint():
        if (budget.get('cancel') and budget['cancel'].is_set()) or time.monotonic()>budget.get('deadline',float('inf')):
            raise ValueError('Arşiv süre sınırı / iptal')
    def read_member(z, info, limit):
        checkpoint()
        if info.file_size > limit or budget['bytes'] + info.file_size > MAX_ARCHIVE_BYTES:
            raise ValueError('Arşiv açma boyutu sınırı')
        budget['bytes'] += info.file_size
        return z.read(info)
    try:
        with zipfile.ZipFile(stream) as z:
            checkpoint()
            entries = z.infolist()
            budget['members'] += len(entries)
            if budget['members'] > MAX_ENTRIES:
                raise ValueError('Arşiv üye sayısı sınırı')
            ids = set()
            classes = sorted({x.filename for x in entries if x.filename.endswith('.class')})
            signature_sizes = {s['size'] for rule in rules['rules'] for s in rule.get('file_signatures', [])}
            detect_chat=any(r['id']=='chat-console-backdoor' for r in rules['rules'])
            for info in entries:
                checkpoint()
                try:
                    if info.filename in ('fabric.mod.json', 'quilt.mod.json'):
                        meta = json.loads(read_member(z, info, MAX_MEMBER))
                        if info.filename == 'quilt.mod.json':
                            meta = meta.get('quilt_loader', {})
                        if isinstance(meta.get('id'), str):
                            ids.add(meta['id'].lower())
                    elif info.filename == 'mcmod.info':
                        meta = json.loads(read_member(z, info, MAX_MEMBER))
                        mods = meta if isinstance(meta, list) else meta.get('modList', [])
                        ids.update(m['modid'].lower() for m in mods if isinstance(m, dict) and isinstance(m.get('modid'), str))
                    elif info.filename in ('META-INF/mods.toml', 'META-INF/neoforge.mods.toml'):
                        meta = tomllib.loads(read_member(z, info, MAX_MEMBER).decode('utf-8'))
                        ids.update(m['modId'].lower() for m in meta.get('mods', []) if isinstance(m.get('modId'), str))
                except (ValueError, KeyError, TypeError, AttributeError, UnicodeError, RuntimeError, OSError, NotImplementedError, zlib.error) as e:
                    issues.append({'path': label, 'reason': f'Metadata okunamadı: {type(e).__name__}'})
            class_set = set(classes)
            for rule in rules['rules']:
                checkpoint()
                matched_ids = sorted(ids.intersection(rule['mod_ids']))
                # Only the first four names are evidence; two distinct hits trigger a rule.
                # Binary prefix lookup preserves that evidence without rescanning all classes.
                selected=set()
                for prefix in rule['class_prefixes']:
                    start=bisect_left(classes,prefix)
                    for name in classes[start:start+4]:
                        if not name.startswith(prefix):break
                        selected.add(name)
                matched_classes=sorted(selected)[:4]
                required = rule.get('required_classes', [])
                matched_signature = required if required and all(c in class_set for c in required) else []
                member_hashes=rule.get('required_member_sha256',{});matched_members=[]
                if member_hashes and all(name in class_set for name in member_hashes):
                    if all(hashlib.sha256(read_member(z,z.getinfo(name),MAX_MEMBER)).hexdigest()==sha for name,sha in member_hashes.items()):matched_members=list(member_hashes)
                if rule['id'] == 'liquidbounce' and ids.intersection({'fdpclient', 'crosssine'}) and not matched_ids:
                    continue
                if matched_ids or len(matched_classes) >= 2 or matched_signature or matched_members:
                    findings.append({
                        'rule': rule['id'], 'name': rule['name'], 'category': rule['category'],
                        'severity': 'review' if rule['category'] == 'automation' else 'high',
                        'path': label, 'method': 'mod-id' if matched_ids else 'member-sha256' if matched_members else 'class-signature' if matched_signature else 'class-namespace',
                        'evidence': matched_ids or ([name+':'+member_hashes[name] for name in matched_members] if matched_members else []) or matched_signature or matched_classes[:4], 'source': rule['source'],
                        'note': ('İstemci eklentisi izi; bağımsız istemci değildir. ' if rule['category'] == 'utility-addon' else 'Dosya içinde istemci/otomasyon izi. ') + 'Çalıştırıldığını veya sunucuda kullanıldığını kanıtlamaz.'
                    })
            for info in entries:
                checkpoint()
                if info.file_size in signature_sizes:
                    content = read_member(z, info, MAX_FILE)
                    findings.extend(match_file_signatures(rules, hashlib.sha256(content).hexdigest(), len(content), label+'!/'+info.filename))
                if info.filename.endswith('.class') and detect_chat:
                    content = b''
                    try:
                        content = read_member(z, info, MAX_MEMBER)
                        if b'hacktheserver' in content:
                            strings, methods = references(content)
                            if known_chat_backdoor(strings, methods):
                                findings.append({'rule':'chat-console-backdoor', 'name':'Sohbetten konsol komutu çalıştıran backdoor izi',
                                  'category':'malware-pattern','severity':'high','path':label+'!/'+info.filename,
                                  'method':'java-constant-pool',
                                  'evidence':['hardcoded chat trigger','org/bukkit/Server.getConsoleSender','org/bukkit/Server.dispatchCommand','AsyncPlayerChatEvent.getMessage'],
                                  'source':'https://mchccbackup.github.io/downloadc.html',
                                  'note':'Dört değiştirilmiş gerçek eklentide doğrulanan statik backdoor deseni. Çalıştırıldığını kanıtlamaz; genel Trojan tespiti değildir.'})
                    except (ValueError, OSError, RuntimeError, NotImplementedError, zlib.error) as exc:
                        issues.append({'path':label+'!/'+info.filename,'reason':'Java incelemesi tamamlanamadı: '+str(exc)[:120]})
                    if content.startswith(b'\xca\xfe\xba\xbe'):
                        continue
                nested = info.filename.lower().endswith('.jar')
                if not nested and info.file_size >= 4:
                    try:
                        with z.open(info) as probe:
                            signature = probe.read(4)
                        nested = signature in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')
                    except (OSError, RuntimeError, ValueError, NotImplementedError, zlib.error) as exc:
                        issues.append({'path': label + '!/' + info.filename, 'reason': 'Arşiv üyesi başlığı okunamadı: ' + type(exc).__name__})
                if nested:
                    if depth >= 2:
                        issues.append({'path': label + '!/' + info.filename, 'reason': 'İç içe arşiv derinlik sınırı'})
                        continue
                    try:
                        content = read_member(z, info, MAX_NESTED)
                        inspect_archive(io.BytesIO(content), label + '!/' + info.filename, rules, findings, issues, depth + 1, budget)
                    except (ValueError, RuntimeError, OSError, NotImplementedError, zlib.error) as e:
                        issues.append({'path': label + '!/' + info.filename, 'reason': str(e)[:150]})
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError, NotImplementedError, zlib.error) as e:
        issues.append({'path': label, 'reason': f'Arşiv okunamadı: {type(e).__name__}: {str(e)[:100]}'})


def scan(root: Path, rules: dict, cancel: threading.Event | None = None, progress=None):
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Minecraft örnek klasörü seçilmeli.')
    cancel = cancel or threading.Event()
    result = {'started_at': now(), 'platform': os.name, 'root': str(root), 'rule_version': rules['version'],
              'files': [], 'findings': [], 'issues': [], 'status': 'completed',
              'coverage': {'file_hashes': True, 'mod_metadata': True, 'class_namespaces': True,
                           'nested_jars': True, 'known_java_backdoor_pattern': True, 'process_memory': False, 'deleted_files': False,
                           'dma_firmware': False, 'server_behavior': False},
              'limitations': ['Seçilen klasörde dosya başlıkları okunur; JAR/ZIP/EXE/DLL/SO ve ZIP/PE/ELF başlıklı dosyalar incelenir.',
                              'Eşleşme olmaması cihazın veya oyuncunun temiz olduğunu kanıtlamaz.',
                              'Dosya kimlikleri değiştirilebilir. Aktif kullanım tespit edilmez.',
                              'Rapor yerel ve imzasızdır; oyuncu tarafından değiştirilebilir.']}
    start, total, visited = time.monotonic(), 0, 0
    def walk_error(e):
        result['issues'].append({'path': str(e.filename), 'reason': 'Klasöre erişilemedi'})
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if not Path(directory, d).is_symlink())
        for name in sorted(names):
            visited += 1
            if cancel.is_set() or visited > MAX_FILES or time.monotonic() - start > MAX_SECONDS:
                result['status'] = 'cancelled' if cancel.is_set() else 'partial'
                result['issues'].append({'path': '.', 'reason': 'İptal edildi' if cancel.is_set() else 'Dosya/süre sınırına ulaşıldı'})
                break
            path = Path(directory, name)
            label = str(path.relative_to(root))
            try:
                if path.is_symlink():
                    result['issues'].append({'path': label, 'reason': 'Sembolik bağlantı atlandı'})
                    continue
                # Check the resolved parent to avoid traversing outside the selected scope.
                if not path.resolve().is_relative_to(root):
                    raise ValueError('Seçilen kapsam dışı yol')
                with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)), 'rb') as f:
                    before = os.fstat(f.fileno())
                    if not stat.S_ISREG(before.st_mode):
                        raise ValueError('Normal dosya değil')
                    magic = f.read(4)
                    kind = 'ZIP' if magic[:2] == b'PK' and magic[2:] in (b'\x03\x04', b'\x05\x06', b'\x07\x08') else 'PE' if magic[:2] == b'MZ' else 'ELF' if magic == b'\x7fELF' else 'other'
                    archive = kind == 'ZIP' or path.suffix.lower() in ('.jar', '.zip')
                    if not archive:
                        archive = zipfile.is_zipfile(f)
                    if kind == 'other' and not archive and path.suffix.lower() not in ('.jar', '.zip', '.exe', '.dll', '.so'):
                        continue
                    if archive and kind != 'ZIP':
                        kind = 'ZIP-overlay'
                    f.seek(0)
                    if before.st_size > MAX_FILE or total + before.st_size > MAX_TOTAL:
                        raise ValueError('Dosya/toplam boyut sınırı')
                    digest = hashlib.sha256()
                    size = 0
                    while block := f.read(1024 * 1024):
                        if cancel.is_set():
                            break
                        size += len(block)
                        if size > MAX_FILE or total + size > MAX_TOTAL:
                            raise ValueError('Okuma boyutu sınırı')
                        digest.update(block)
                    total += size
                    if cancel.is_set():
                        result['status'] = 'cancelled'
                        break
                    after = os.fstat(f.fileno())
                    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                        raise ValueError('Dosya tarama sırasında değişti')
                    sha = digest.hexdigest()
                    record = {'path': label, 'sha256': sha, 'size': size, 'format': kind,
                              'modified_at': datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat()}
                    result['files'].append(record)
                    result['findings'].extend(match_file_signatures(rules, sha, size, label))
                    if sha in rules['hashes']:
                        result['findings'].append({'rule': 'sha256', 'name': rules['hashes'][sha], 'category': 'custom',
                            'severity': 'high', 'path': label, 'method': 'sha256', 'evidence': [sha], 'source': 'local-rule',
                            'note': 'Yerel kural dosyasıyla tam hash eşleşmesi. Kuralın doğruluğu incelenmeli.'})
                    if archive:
                        f.seek(0)
                        inspect_archive(f, label, rules, result['findings'], result['issues'], budget={'members':0,'bytes':0,'deadline':min(start+MAX_SECONDS,time.monotonic()+MAX_ARCHIVE_SECONDS),'cancel':cancel})
                    if (after.st_size, after.st_mtime_ns) != (os.fstat(f.fileno()).st_size, os.fstat(f.fileno()).st_mtime_ns):
                        result['issues'].append({'path': label, 'reason': 'Arşiv incelemesinde dosya değişti'})
            except (OSError, ValueError) as e:
                result['issues'].append({'path': label, 'reason': str(e)[:180]})
            if progress:
                progress(len(result['files']), label)
        if result['status'] != 'completed':
            break
    if result['issues'] and result['status'] == 'completed':
        result['status'] = 'partial'
    result['finished_at'] = now()
    result['duration_seconds'] = round(time.monotonic() - start, 3)
    result['bytes_read'] = total
    result['verdict'] = 'review' if result['findings'] else 'no_match'
    return result
