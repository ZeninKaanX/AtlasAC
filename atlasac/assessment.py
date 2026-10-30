"""Conservative evidence semantics: static identity never establishes game use."""
import unicodedata

LEVELS={
    'file-sha256':'exact-file', 'member-sha256':'exact-members',
    'sha256':'local-hash', 'class-signature':'class-layout',
    'class-namespace':'namespace', 'mod-id':'declared-metadata',
    'java-constant-pool':'static-code-pattern',
}

def classify(findings):
    for row in findings:
        row.update(evidence_level=LEVELS.get(row.get('method'),'unclassified'),
                   observed_state='static-file', usage_proven=False,
                   session_link='not-established', active_features='not-established')
    return findings


def name_context(path):
    """Letters from Turkish and other languages are normal; only format controls listed."""
    name=path.name
    if name.isascii():return None
    controls=[f'U+{ord(c):04X} {unicodedata.name(c,"UNKNOWN")}' for c in name if unicodedata.category(c)=='Cf']
    if not controls:return None
    return {'path':str(path),'escaped_name':name.encode('unicode_escape').decode('ascii'),
            'controls':sorted(set(controls)), 'classification':'filename-context',
            'usage_proven':False,'note':'Biçim/yön kontrol karakteri; tek başına hile veya gizleme kanıtı değildir.'}


def process_context(rows):
    jvm=[];macros=[]
    for row in rows:
        argv=row.get('cmdline') or []
        if not isinstance(argv,list) or not argv:continue
        # Use original argv; never execute a command or split quoted Windows arguments heuristically.
        name=(row.get('name') or '').lower()
        if name in ('java','java.exe','javaw','javaw.exe'):
            selected=[]
            paired={'-jar','-cp','-classpath','--class-path','--gameDir'}
            for i,arg in enumerate(argv[1:],1):
                if not isinstance(arg,str):continue
                if arg in paired:
                    selected.append({'option':arg,'value':argv[i+1] if i+1<len(argv) else ''})
                elif arg.startswith(('-javaagent:','-agentlib:','-agentpath:','--gameDir=')):
                    selected.append({'option':arg.split(':',1)[0].split('=',1)[0],
                                     'value':arg.split(':',1)[1] if ':' in arg else arg.split('=',1)[1]})
                elif arg in ('net.minecraft.client.main.Main','net.minecraft.launchwrapper.Launch','org.multimc.EntryPoint','net.fabricmc.loader.impl.launch.knot.KnotClient'):
                    selected.append({'option':'main-class','value':arg})
            jvm.append({'pid':row.get('pid'),'process':name,'started_at':row.get('started_at',''),
                        'options':selected,'classification':'jvm-launch-context','usage_proven':False,
                        'note':'JVM seçenekleri envanteri; agent veya oyun başlatılması hile kanıtı değildir. Gizli erişim belirteci seçenekleri eklenmez.'})
        if name in ('autohotkey.exe','autohotkey64.exe','autohotkey32.exe','autohotkeyu64.exe','autohotkeyu32.exe','autoit3.exe','autoit3_x64.exe'):
            scripts=[a for a in argv[1:] if isinstance(a,str) and a.lower().endswith(('.ahk','.au3'))]
            macros.append({'pid':row.get('pid'),'process':name,'scripts':scripts,
                           'classification':'automation-context','usage_proven':False,
                           'note':'Otomasyon/erişilebilirlik aracı; script içeriği veya oyunda kullanımı doğrulanmadı.'})
    return {'jvm_context':jvm,'macro_context':macros}


def report_verdict(report):
    if report.get('findings'):return 'review'
    if report.get('artifacts',{}).get('review_signals'):return 'context_review'
    return 'no_match'
