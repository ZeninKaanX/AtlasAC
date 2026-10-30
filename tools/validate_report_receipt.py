"""Exercise a frozen binary's independent-digest verification without any cheat execution."""
import argparse,json,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from atlasac.integrity import attach_receipt


def validate(binary):
    with tempfile.TemporaryDirectory(prefix='atlasac-receipt-') as tmp:
        root=Path(tmp);source=root/'report.json';output=root/'verification.json'
        original=attach_receipt({'application':'AtlasAC','status':'partial','findings':[{'rule':'fixture','path':'fixture.jar'}]})
        expected=original['report_receipt']['payload_sha256']
        cases=[('original',original,0,True)]
        changed=json.loads(json.dumps(original));changed['findings']=[];changed['status']='completed'
        cases.append(('removed-findings',changed,2,False))
        cases.append(('recomputed-player-checksum',attach_receipt(changed),2,False))
        for label,report,code,matches in cases:
            source.write_text(json.dumps(report,ensure_ascii=False),encoding='utf-8');output.unlink(missing_ok=True)
            result=subprocess.run([str(binary.resolve()),'--verify-report',str(source),'--expected-digest',expected,'--output',str(output)],capture_output=True,timeout=60)
            assert result.returncode==code,(label,result.returncode,result.stderr[-300:])
            verified=json.loads(output.read_text(encoding='utf-8'))
            assert verified['checksum_matches'] is matches,label
            assert verified['compared_with_external_digest'] and not verified['digital_signature'] and not verified['host_verified'],label
        print('Frozen receipt verification: 3/3 cases passed; no host/signature claim')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path)
    validate(parser.parse_args().binary)
