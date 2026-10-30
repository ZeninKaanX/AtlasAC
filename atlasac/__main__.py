import argparse
import json
from pathlib import Path
import sys
from .engine import load_rules, scan
from .paths import RULES
from .privacy import notice_text,minimize_report
from .securestore import write_json
from .integrity import verify_receipt,attach_receipt,require_official_rules


def main():
    parser = argparse.ArgumentParser(description='AtlasAC — yerel masaüstü hile kontrol aracı')
    parser.add_argument('--scan', type=Path, help='Komut satırından seçilen klasörü incele')
    parser.add_argument('--system-scan', action='store_true', help='Tüm yerel diskleri ve sistem kayıtlarını incele')
    parser.add_argument('--consent', action='store_true', help='Seçilen klasörün incelenmesine onay')
    parser.add_argument('--max-seconds',type=float,default=None,help='İsteğe bağlı sistem tarama sınırı (saniye); verilmezse süre sınırı yok')
    parser.add_argument('--rules', type=Path, default=RULES)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify-report',type=Path,help='JSON raporunun içerik özetini kontrol et; dijital imza değildir')
    parser.add_argument('--expected-digest',help='Denetleyen kişinin bağımsız sakladığı özgün SHA-256 özeti')
    args = parser.parse_args()
    if args.verify_report:
        try:
            if args.verify_report.stat().st_size>16*1024*1024:raise ValueError('Rapor boyut sınırı')
            value=json.loads(args.verify_report.read_text(encoding='utf-8'))
            if not isinstance(value,dict):raise ValueError('Geçersiz rapor')
            result=verify_receipt(value,args.expected_digest)
            if args.output:write_json(args.output,result)
            else:print(json.dumps(result,ensure_ascii=False,indent=2))
            return 0 if result['checksum_matches'] else 2
        except (OSError,ValueError) as exc:print('AtlasAC: '+str(exc),file=sys.stderr);return 1
    if args.expected_digest:parser.error('--expected-digest için --verify-report gerekli')
    if args.scan or args.system_scan:
        if not args.consent:
            parser.error('--scan için --consent gerekli')
        print(notice_text(),file=sys.stderr)
        try:
            rules=load_rules(args.rules);require_official_rules(rules)
            if args.system_scan:
                from .systemscan import system_scan
                from .scanprocess import run_scan
                from .systemscan import computer_roots
                import threading
                report = run_scan(rules,computer_roots(),None,True,threading.Event(),lambda data:None,max_seconds=args.max_seconds)
            else:
                report = scan(args.scan, rules)
            report=attach_receipt(report)
            content = json.dumps(report, ensure_ascii=False, indent=2)
            if args.output:
                write_json(args.output,report)
            else:
                print(content)
            return 2 if report['status'] != 'completed' else 0
        except (ValueError, OSError) as e:
            print(f'AtlasAC: {e}', file=sys.stderr)
            return 1
    try:
        from .desktop import run_desktop
    except ImportError as e:
        print(f'AtlasAC masaüstü bileşeni yüklenemedi: {e}. Kaynaktan çalıştırırken requirements.txt kurun.', file=sys.stderr)
        return 1
    return run_desktop(args.rules)


if __name__ == '__main__':
    from multiprocessing import freeze_support
    freeze_support()
    sys.exit(main())
