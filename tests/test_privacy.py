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
        import ctypes as c
        from ctypes import wintypes as w
        from atlasac.securestore import current_sid
        adv=c.WinDLL('advapi32',use_last_error=True);kernel=c.WinDLL('kernel32',use_last_error=True)
        adv.GetNamedSecurityInfoW.argtypes=[w.LPWSTR,c.c_int,w.DWORD,c.c_void_p,c.c_void_p,c.POINTER(c.c_void_p),c.c_void_p,c.POINTER(c.c_void_p)]
        adv.GetNamedSecurityInfoW.restype=w.DWORD
        adv.GetSecurityDescriptorControl.argtypes=[c.c_void_p,c.POINTER(w.WORD),c.POINTER(w.DWORD)];adv.GetSecurityDescriptorControl.restype=w.BOOL
        adv.GetAclInformation.argtypes=[c.c_void_p,c.c_void_p,w.DWORD,c.c_int];adv.GetAclInformation.restype=w.BOOL
        adv.GetAce.argtypes=[c.c_void_p,w.DWORD,c.POINTER(c.c_void_p)];adv.GetAce.restype=w.BOOL
        adv.ConvertSidToStringSidW.argtypes=[c.c_void_p,c.POINTER(w.LPWSTR)];adv.ConvertSidToStringSidW.restype=w.BOOL
        kernel.LocalFree.argtypes=[c.c_void_p]
        class AclSize(c.Structure):
            _fields_=[('count',w.DWORD),('used',w.DWORD),('free',w.DWORD)]
        with tempfile.TemporaryDirectory() as tmp:
            root=private_directory(Path(tmp)/'private');path=root/'report.json';write_json(path,{})
            for target in (root,path):
                descriptor=c.c_void_p();acl=c.c_void_p()
                code=adv.GetNamedSecurityInfoW(str(target),1,4,None,None,c.byref(acl),None,c.byref(descriptor))
                self.assertEqual(code,0)
                try:
                    control=w.WORD();revision=w.DWORD();info=AclSize()
                    self.assertTrue(adv.GetSecurityDescriptorControl(descriptor,c.byref(control),c.byref(revision)))
                    self.assertTrue(control.value&0x1000,'DACL must be protected from parent inheritance')
                    self.assertTrue(acl.value,'NULL DACL would allow everyone')
                    self.assertTrue(adv.GetAclInformation(acl,c.byref(info),c.sizeof(info),2))
                    self.assertEqual(info.count,2);sids=set()
                    for i in range(info.count):
                        ace=c.c_void_p();self.assertTrue(adv.GetAce(acl,i,c.byref(ace)))
                        self.assertEqual(c.c_ubyte.from_address(ace.value).value,0,'Only allow ACEs expected')
                        self.assertFalse(c.c_ubyte.from_address(ace.value+1).value&0x10,'No inherited ACEs expected')
                        self.assertEqual(c.c_uint32.from_address(ace.value+4).value&0x1f01ff,0x1f01ff,'Full control for authorised SID')
                        text=w.LPWSTR()
                        self.assertTrue(adv.ConvertSidToStringSidW(c.c_void_p(ace.value+8),c.byref(text)))
                        try:sids.add(text.value)
                        finally:kernel.LocalFree(c.cast(text,c.c_void_p))
                    self.assertEqual(sids,{current_sid(),'S-1-5-18'})
                finally:kernel.LocalFree(descriptor)
