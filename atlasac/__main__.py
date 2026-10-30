import argparse
import json
from pathlib import Path
import sys
from .engine import load_rules, scan
from .paths import RULES
from .privacy import notice_text,minimize_report
from .securestore import write_json


def main():
    parser = argparse.ArgumentParser(description='AtlasAC — yerel masaüstü hile kontrol aracı')
    parser.add_argument('--scan', type=Path, help='Komut satırından seçilen klasörü incele')
    parser.add_argument('--system-scan', action='store_true', help='Tüm yerel diskleri ve sistem kayıtlarını incele')
    parser.add_argument('--consent', action='store_true', help='Seçilen klasörün incelenmesine onay')
    parser.add_argument('--max-seconds',type=float,default=600,help='Sistem tarama süresi; en fazla 600 saniye')
    parser.add_argument('--rules', type=Path, default=RULES)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.scan or args.system_scan:
        if not args.consent:
            parser.error('--scan için --consent gerekli')
        print(notice_text(),file=sys.stderr)
        try:
            if args.system_scan:
                from .systemscan import system_scan
                from .scanprocess import run_scan
                from .systemscan import computer_roots
                import threading
                report = run_scan(load_rules(args.rules),computer_roots(),None,True,threading.Event(),lambda data:None,max_seconds=args.max_seconds)
            else:
                report = scan(args.scan, load_rules(args.rules))
            report=minimize_report(report)
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
