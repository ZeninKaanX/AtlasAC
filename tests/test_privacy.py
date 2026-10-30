import base64,json,os,sqlite3,tempfile,threading,time,unittest
from pathlib import Path
from unittest.mock import patch
from atlasac.privacy import redact_text,safe_argv,minimize_report,safe_url,notice_text
from atlasac.reports import ReportHistory
from atlasac.index import FileIndex,purge_index
from atlasac.securestore import private_directory,write_json
from atlasac.collectors import collect_browsers
from atlasac.commandtraces import analyze,read_history
from atlasac.audit import AuditTrail

class PrivacyTests(unittest.TestCase):
    def test_known_secrets_in_command_formats_are_removed_without_running_commands(self):
        marker='TEST_ONLY_SECRET_4729'
        for command in [f'password={marker}',f'tool --password {marker}',f'tool /password:{marker}',f'curl -H "Authorization: Bearer {marker}"',f'curl -H "Authorization: Basic {marker}"',f'https://user:{marker}@example.invalid/download.jar?token={marker}#fragment',f'curl -H "Cookie: session={marker}; next=value"',f'{{"password": "{marker}"}}',f"secret='{marker}'"]:
            self.assertNotIn(marker,redact_text(command),command)
        self.assertEqual(safe_argv(['java','--accessToken',marker,'--gameDir','/mods'])[2],'[REDACTED]')
        self.assertEqual(redact_text('wevtutil cl Security'),'wevtutil cl Security')

    def test_encoded_commands_mask_secrets_but_retain_review_evidence(self):
        raw='Clear-History; tool --password TEST_ONLY_SECRET_4729'
        encoded=base64.b64encode(raw.encode('utf-16-le')).decode()
        clean=redact_text('powershell -EncodedCommand '+encoded)
        decoded=base64.b64decode(clean.split()[-1]).decode('utf-16-le')
        self.assertNotIn('TEST_ONLY_SECRET_4729',decoded)
        self.assertIn('Clear-History',decoded)
        self.assertEqual(analyze([{'command':clean}])[0]['rule'],'history-clear-command')
        argv=safe_argv(['powershell.exe','-EncodedCommand',encoded])
        self.assertNotIn('TEST_ONLY_SECRET_4729',base64.b64decode(argv[-1]).decode('utf-16-le'))

    def test_report_boundary_masks_legacy_data_and_removes_general_browsing(self):
        report={'artifacts':{'history':[{'url':'https://private.invalid'}],'processes':[{'username':'other-user','cmdline':['tool','--password','TEST_ONLY_SECRET_4729']}],'usb':[{'serial':'unique','instance':'unique'}]},'token':'TEST_ONLY_SECRET_4729'}
        clean=minimize_report(report)
        self.assertNotIn('TEST_ONLY_SECRET_4729',json.dumps(clean));self.assertNotIn('history',clean['artifacts'])
        self.assertNotIn('username',clean['artifacts']['processes'][0]);self.assertFalse(clean['artifacts']['usb'][0])
        self.assertIn('history',report['artifacts'])  # Do not mutate caller's report.
        self.assertEqual(safe_url('https://u:p@example.invalid/client.jar?a=b#c'),'https://example.invalid/client.jar')

    def test_export_private_permissions_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'export.json';write_json(path,{'command':'tool --password TEST_ONLY_SECRET_4729'})
            self.assertNotIn('TEST_ONLY_SECRET_4729',path.read_text())
            if os.name!='nt':
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                link=root/'link.json';link.symlink_to(path)
                with self.assertRaises(OSError):write_json(link,{})
            self.assertFalse(list(root.glob('.atlasac-*.tmp')))

    def test_existing_reports_migrate_without_extending_age_and_expire(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);report=root/'2026-10-29-old.json'
            report.write_text(json.dumps({'artifacts':{'history':[{'url':'https://private.invalid'}]},'command':'tool --password TEST_ONLY_SECRET_4729'}))
            stamp=time.time()-3600;os.utime(report,(stamp,stamp))
            history=ReportHistory(root)
            self.assertNotIn('TEST_ONLY_SECRET_4729',report.read_text());self.assertNotIn('history',json.loads(report.read_text())['artifacts'])
            self.assertAlmostEqual(report.stat().st_mtime,stamp,places=3)
            if os.name!='nt':self.assertEqual(root.stat().st_mode&0o777,0o700)
            old=time.time()-8*86400;os.utime(report,(old,old));history.maintain();self.assertFalse(report.exists())

    def test_index_migrates_old_cache_prunes_by_age_and_protects_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'file-index.sqlite3'
            db=sqlite3.connect(path);db.execute('CREATE TABLE files(path TEXT PRIMARY KEY,size INTEGER,modified_ns INTEGER,kind TEXT,sha256 TEXT,scan_id TEXT,token TEXT,cache TEXT)');db.execute("INSERT INTO files VALUES('legacy',1,1,'','','','','')");db.commit();db.close()
            index=FileIndex(path)
            self.assertFalse(index.db.execute('SELECT * FROM files').fetchall())
            index.db.execute("INSERT INTO files VALUES('expired',1,1,'','','','','',?)",(time.time()-8*86400,));index.close()
            index=FileIndex(path);self.assertFalse(index.db.execute('SELECT * FROM files').fetchall())
            if os.name!='nt':
                self.assertEqual(path.stat().st_mode&0o777,0o600)
                for suffix in ('-wal','-shm'):
                    side=Path(str(path)+suffix)
                    if side.exists():self.assertEqual(side.stat().st_mode&0o777,0o600)
            index.close();(root/'unrelated.txt').write_text('keep');purge_index(root)
            self.assertFalse(path.exists());self.assertTrue((root/'unrelated.txt').exists())

    def test_browser_only_relevant_downloads_without_query_or_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'History';db=sqlite3.connect(path)
            db.execute('CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER,visit_count INTEGER)');db.execute("INSERT INTO urls VALUES('https://private.invalid','private',1,1)")
            db.execute('CREATE TABLE downloads(id INTEGER,target_path TEXT,start_time INTEGER,tab_url TEXT)')
            db.executemany('INSERT INTO downloads VALUES(?,?,?,?)',[(1,'/mods/client.jar',1,'https://example.invalid/client.jar?token=TEST_ONLY_SECRET_4729'),(2,'/docs/private.pdf',1,'https://private.invalid/document.pdf')]);db.commit();db.close()
            with patch('atlasac.collectors.browser_profiles',return_value=[('Chrome','Default',path,'chromium')]):rows,errors,count=collect_browsers(threading.Event())
            self.assertFalse(errors);self.assertNotIn('history',rows);self.assertEqual(len(rows['downloads']),1)
            self.assertEqual(rows['downloads'][0]['url'],'https://example.invalid/client.jar');self.assertNotIn('private.invalid',str(rows))
            self.assertTrue(path.exists())

    def test_audit_bounded_minimal_and_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit=AuditTrail(tmp);audit.record('scan-start');audit.record('report-export',1)
            self.assertEqual(set(audit.rows[0]),{'time','event','count'})
            self.assertEqual(audit.purge(),1);self.assertFalse(audit.path.exists())
        self.assertIn('TrueFormTech',notice_text());self.assertIn('trueformtechx@gmail.com',notice_text())

    @unittest.skipUnless(os.name=='nt','Windows DACL integration')
    def test_windows_dacl_is_protected_and_contains_only_current_user_and_system(self):
        import subprocess
        from atlasac.securestore import current_sid
        with tempfile.TemporaryDirectory() as tmp:
            root=private_directory(Path(tmp)/'private');path=root/'report.json';write_json(path,{})
            script='$a=Get-Acl -LiteralPath $args[0]; [pscustomobject]@{protected=$a.AreAccessRulesProtected;aces=@($a.Access|ForEach-Object{[pscustomobject]@{sid=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value;inherited=$_.IsInherited;type=[string]$_.AccessControlType}})}|ConvertTo-Json -Depth 4 -Compress'
            for target in (root,path):
                # Script file avoids command interpolation of paths.
                file=Path(tmp)/'verify.ps1';file.write_text(script,encoding='utf-8')
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(file),str(target)],capture_output=True,check=True)
                data=json.loads(result.stdout.decode('utf-8-sig'))
                self.assertTrue(data['protected']);self.assertEqual({r['sid'] for r in data['aces']},{current_sid(),'S-1-5-18'})
                self.assertTrue(all(not r['inherited'] and r['type']=='Allow' for r in data['aces']))
