"""Statically validate pinned samples: --samples-dir /private/samples --output report.json.

Download exact manifest URLs separately and save under their `file` names.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from atlasac.engine import load_rules, now
from atlasac.fileprobe import probe
from atlasac.systemscan import system_scan


def validate(samples, manifest):
    rules = load_rules(Path(__file__).resolve().parents[1]/'rules/default.json')
    result = {'at': now(), 'platform': sys.platform, 'rule_version': rules['version'],
              'sample_execution': False, 'tests': [], 'all_passed': True}
    with tempfile.TemporaryDirectory(prefix='atlasac-ghost-') as tmp:
        root = Path(tmp).resolve(); disk = root/'disk'; disk.mkdir()
        expected_paths = {}
        for number, sample in enumerate(manifest['samples']):
            content = (samples/sample['file']).read_bytes()
            if len(content) != sample['size'] or hashlib.sha256(content).hexdigest() != sample['sha256']:
                raise ValueError('Sample identity mismatch: '+sample['id'])
            target = disk/f'{number:02}.dat'; target.write_bytes(content)
            expected_paths[str(target)] = sample['expected']
            variants = [('renamed', content)]
            if zipfile.is_zipfile(io.BytesIO(content)) and sample['expected']:
                buf = io.BytesIO()
                with zipfile.ZipFile(io.BytesIO(content)) as src, zipfile.ZipFile(buf,'w') as dest:
                    for info in src.infolist():
                        if info.filename.endswith('.class'):
                            dest.writestr(info.filename, src.read(info))
                variants.append(('metadata-removed', buf.getvalue()))
            if sample['expected']:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf,'w') as z: z.writestr('payload/data.bin', content)
                variants.append(('nested', buf.getvalue()))
            for variant, data in variants:
                path = root/'variant.dat'; path.write_bytes(data)
                report = probe(path, rules, threading.Event())
                actual = sorted({f['rule'] for f in report['findings']})
                passed = actual == sample['expected'] and not report['issues']
                result['tests'].append({'sample': sample['id'], 'variant': variant, 'sha256': sample['sha256'],
                                        'expected': sample['expected'], 'actual': actual,
                                        'methods': sorted({f['method'] for f in report['findings']}),
                                        'issues': report['issues'], 'passed': passed})
                result['all_passed'] &= passed
        for pass_number in range(2):
            events = []
            report = system_scan(rules, [disk], artifacts=False, data_dir=root/'state', progress=events.append)
            live = [f for event in events for f in event['new_findings']]
            final_rows = sorted((f['path'], f['rule']) for f in report['findings'])
            expected_rows = sorted((p, r) for p, rules_for_path in expected_paths.items() for r in rules_for_path)
            passed = (report['status'] == 'completed' and final_rows == expected_rows
                      and sorted((f['path'], f['rule']) for f in live) == expected_rows)
            result['tests'].append({'variant': 'cold-system' if not pass_number else 'cached-system',
                                    'expected_matches': len(expected_rows), 'matches': len(final_rows),
                                    'live_matches': len(live), 'cache_hits': report['cache_hits'],
                                    'files': report['content_files'], 'status': report['status'], 'passed': passed})
            result['all_passed'] &= passed
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--expansion-only', action='store_true', help='Only the newly added sample builds and benign controls')
    parser.add_argument('--download', action='store_true', help='Fetch exact pinned public builds; never execute them')
    args = parser.parse_args()
    manifest = json.loads((Path(__file__).resolve().parents[1]/'docs/ghost-samples-035.json').read_text())
    if args.expansion_only:
        manifest['samples'] = [s for s in manifest['samples'] if not s['id'].startswith('doomsday-')]
    if args.download:
        args.samples_dir.mkdir(parents=True, exist_ok=True)
        for sample in manifest['samples']:
            request = urllib.request.Request(sample['url'], headers={'User-Agent': 'AtlasAC-static-validation'})
            with urllib.request.urlopen(request, timeout=30) as response:
                content = response.read(32*1024*1024+1)
            if len(content) != sample['size'] or hashlib.sha256(content).hexdigest() != sample['sha256']:
                raise ValueError('Published bytes changed; refusing to validate as pinned sample: '+sample['id'])
            (args.samples_dir/sample['file']).write_bytes(content)
    result = validate(args.samples_dir, manifest)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'all_passed': result['all_passed'], 'checks': len(result['tests'])}))
    raise SystemExit(0 if result['all_passed'] else 1)
