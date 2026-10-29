"""Fetch public release candidates, inspect bytes, and report an honest static benchmark.

No sample is imported, unpacked to disk, or executed. This is not an in-game test.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import io
import json
from pathlib import Path
import sys
import ssl
import time
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from atlasac.engine import inspect_archive, load_rules, MAX_FILE, now


def inventory(path):
    with zipfile.ZipFile(path) as z:
        names=z.namelist()
        nested_classes=0
        if not any(n.endswith('.class') for n in names):
            for name in names:
                if name.endswith('.jar') and z.getinfo(name).file_size <= 16*1024*1024:
                    with zipfile.ZipFile(io.BytesIO(z.read(name))) as nested:
                        nested_classes += sum(n.endswith('.class') for n in nested.namelist())
            if not nested_classes:
                raise ValueError('Derlenmiş Java sınıfı yok; gerçek ikili örnek olarak kabul edilmedi.')
        ids=[]
        for name in ('fabric.mod.json','quilt.mod.json','mcmod.info','META-INF/mods.toml','META-INF/neoforge.mods.toml'):
            if name in names:
                info=z.getinfo(name)
                if info.file_size <= 512*1024:
                    ids.append({'member':name,'text':z.read(info).decode('utf-8',errors='replace')[:12000]})
        counts={}
        for n in names:
            if n.endswith('.class'):
                prefix='/'.join(n.split('/')[:3])
                counts[prefix]=counts.get(prefix,0)+1
        return {'classes':sum(n.endswith('.class') for n in names),'nested_classes':nested_classes,'metadata':ids,'top_namespaces':sorted(counts.items(),key=lambda x:-x[1])[:10]}


def one(sample, cache, rules):
    row={k:sample[k] for k in ('sample_id','repo','release','name','url','family','category','expected')}
    row['role']=sample.get('role','validation')
    row['status']='acquisition_error'
    folder=cache/hashlib.sha256(sample['url'].encode()).hexdigest()[:24]
    path=folder/'sample.dat'
    start=time.monotonic()
    try:
        folder.mkdir(parents=True,exist_ok=True)
        if not path.exists():
            tmp=folder/'download.part'
            request=urllib.request.Request(sample['url'],headers={'User-Agent':'AtlasAC-Static-Benchmark/0.1'})
            try:
                try:
                    from pip._vendor import certifi
                    tls = ssl.create_default_context(cafile=certifi.where())
                except ImportError:
                    tls = ssl.create_default_context()
                with urllib.request.urlopen(request,timeout=45,context=tls) as res, tmp.open('wb') as out:
                    count=0
                    while block:=res.read(1024*1024):
                        count+=len(block)
                        if count>MAX_FILE:raise ValueError('Örnek boyutu sınırı aşıldı.')
                        out.write(block)
                tmp.replace(path)
            finally:
                tmp.unlink(missing_ok=True)
        with path.open('rb') as source:
            data_hash=hashlib.file_digest(source,'sha256').hexdigest()
        row['sha256']=data_hash;row['size']=path.stat().st_size
        expected_digest=sample.get('digest')
        if expected_digest and expected_digest != 'sha256:'+data_hash:
            raise ValueError('Yayıncı SHA-256 bilgisiyle eşleşmedi.')
        if sample.get('expected_sha512'):
            with path.open('rb') as source:
                if hashlib.file_digest(source,'sha512').hexdigest() != sample['expected_sha512']:
                    raise ValueError('Yayıncı SHA-512 bilgisiyle eşleşmedi.')
        row['publisher_digest_verified']=bool(expected_digest or sample.get('expected_sha512'))
        row['inventory']=inventory(path)
        findings=[];issues=[]
        inspect_archive(path, sample['name'], rules, findings, issues)
        row['findings']=findings;row['issues']=issues
        row['status']='partial' if issues else 'tested'
        row['expected_family_matched']=any(f['rule']==sample['family'] for f in findings)
        row['any_detection']=bool(findings)
        row['passed']=not issues and (row['expected_family_matched'] if sample['expected']=='detection' else not findings)
    except Exception as exc:
        row['error']=f'{type(exc).__name__}: {exc}'[:400]
    row['duration_seconds']=round(time.monotonic()-start,3)
    return row


def summarize(rows, manifest):
    unique={};duplicates=[]
    for row in rows:
        if row['status'] not in ('tested','partial'):continue
        digest=row['sha256']
        if digest in unique:duplicates.append(row['sample_id'])
        else:unique[digest]=row
    accepted=list(unique.values())
    discovery=[r for r in accepted if r.get('role')=='discovery']
    positives=[r for r in accepted if r['expected']=='detection' and r.get('role')!='discovery']
    passed=[r for r in positives if r.get('passed')]
    clients={r['family'] for r in positives if r['category']=='client'}
    families={r['family'] for r in positives}
    negatives=[r for r in accepted if r['expected']=='no_detection']
    return {'requested':len(rows),'discovery_files_excluded':len(discovery),'acquired_unique_files':len(accepted),'unique_positive_files':len(positives),
            'distinct_client_families':len(clients),'distinct_families_including_addons_and_automation':len(families),
            'positive_passed':len(passed),'positive_failed_or_partial':len(positives)-len(passed),
            'negative_files':len(negatives),'false_positive_files':sum(bool(r.get('any_detection')) for r in negatives),
            'acquisition_errors':sum(r['status']=='acquisition_error' for r in rows),'duplicate_files_excluded':len(duplicates),
            'file_target_met':len(passed)>=manifest.get('target_unique_files',200),
            'family_target_met':len(clients)>=manifest.get('target_distinct_client_families',200),
            'overall_target_met':len(passed)>=manifest.get('target_unique_files',200) and len(clients)>=manifest.get('target_distinct_client_families',200),
            'test_type':'static-file-inspection-only','executed_samples':0,
            'limitations':['Bilinmeyen veya gelecekteki hileler için garanti değildir.','İstemcilerin oyunda çalıştırılması, bellek veya DMA testi değildir.','Aynı ailenin farklı sürümleri ayrı aile sayılmaz.','Negatif örnek bulunmuyorsa yanlış pozitif başarımı ölçülmüş sayılmaz.']}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--cache',type=Path,required=True)
    p.add_argument('--rules',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--workers',type=int,default=6)
    args=p.parse_args()
    manifest=json.loads(args.manifest.read_text(encoding='utf-8'));rules=load_rules(args.rules)
    rows=[];started=now()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    def write():
        content={'started_at':started,'updated_at':now(),'rule_version':rules['version'],'scanner_source_sha256':hashlib.sha256(Path(sys.modules[inspect_archive.__module__].__file__).read_bytes()).hexdigest(),'rule_file_sha256':hashlib.sha256(args.rules.read_bytes()).hexdigest(),'summary':summarize(rows,manifest),'samples':rows}
        args.output.write_text(json.dumps(content,ensure_ascii=False,indent=2),encoding='utf-8')
    with ThreadPoolExecutor(max_workers=max(1,min(args.workers,8))) as pool:
        futures=[pool.submit(one,s,args.cache,rules) for s in manifest['samples']]
        for future in as_completed(futures):
            r=future.result();rows.append(r);write()
            print(f"{len(rows)}/{len(futures)} {r['family']}: {r['status']} pass={r.get('passed',False)}",flush=True)
    write();print(json.dumps(summarize(rows,manifest),ensure_ascii=False,indent=2))
    return 0 if summarize(rows,manifest)['overall_target_met'] else 2

if __name__=='__main__':raise SystemExit(main())
