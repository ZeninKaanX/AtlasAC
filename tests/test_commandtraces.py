import base64,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
from atlasac.commandtraces import analyze,parse_events,read_history,collect_command_traces

class CommandTests(unittest.TestCase):
    def record(self,command):return {'kind':'history','source':'history-fixture','command':command}
    def test_targeted_patterns_and_encoded_command_are_review_not_cheat_proof(self):
        commands=['wevtutil cl Security','Clear-History','Remove-Item "$env:APPDATA/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"','fsutil usn deletejournal /d C:','cipher /w:C:','auditpol /clear']
        for command in commands:
            hits=analyze([self.record(command)])
            self.assertTrue(hits,command);self.assertTrue(all(x['severity']=='review' and x['category']=='anti-forensics' for x in hits))
        encoded=base64.b64encode('Clear-History'.encode('utf-16-le')).decode()
        hits=analyze([self.record('powershell.exe -EncodedCommand '+encoded)])
        self.assertEqual(hits[0]['rule'],'history-clear-command');self.assertIn('çalıştırılmadı',hits[0]['note'])
    def test_ordinary_commands_comments_and_quoted_examples_are_not_alerts(self):
        for text in ['Get-Process','del report.txt','Remove-Item build -Recurse','Write-Output "wevtutil cl Security"','Write-Output "example; Clear-History"','# Clear-History','echo harmless']:
            self.assertFalse(analyze([self.record(text)]),text)
        self.assertTrue(analyze([self.record('echo hello; Clear-History')]))
    def test_event_provenance_and_process_command(self):
        xml='''<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event><System><Provider Name="Microsoft-Windows-Eventlog"/><EventID>1102</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-10-29T12:00:00Z"/></System></Event></Events>'''
        rows=parse_events(xml,'Security');hits=analyze(rows)
        self.assertEqual(hits[0]['rule'],'log-cleared');self.assertEqual(hits[0]['record_id'],'42')
        self.assertFalse(parse_events(xml.replace('Microsoft-Windows-Eventlog','Unrelated'),'Security'))
        xml='''<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><Event><System><EventID>4688</EventID></System><EventData><Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c echo safe</Data></EventData></Event></Events>'''
        self.assertEqual(parse_events(xml,'Security')[0]['command'],'cmd.exe /c echo safe')
    def test_history_read_does_not_change_source_and_masks_common_secret_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ConsoleHost_history.txt';raw=b'Get-Process\npassword=private-value\nClear-History\n';path.write_bytes(raw)
            rows,limited=read_history(path,100)
            self.assertEqual(path.read_bytes(),raw);self.assertFalse(limited)
            self.assertNotIn('private-value',str(rows));self.assertEqual(len(analyze(rows)),1)
    def test_missing_history_is_coverage_gap_not_suspicion(self):
        with patch('atlasac.commandtraces.history_files',return_value=iter(())),patch('atlasac.commandtraces.live_commands',return_value=[]),patch('atlasac.commandtraces.os.name','posix'):
            rows,alerts,component=collect_command_traces(threading.Event())
        self.assertFalse(alerts);self.assertEqual(component['status'],'partial')
        self.assertEqual(rows['command_coverage'][0]['status'],'unavailable')

    def test_command_alerts_publish_before_files_and_survive_final_report(self):
        from atlasac.systemscan import system_scan
        from atlasac.engine import load_rules
        from atlasac.paths import RULES
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'disk';root.mkdir();(root/'ordinary.dat').write_text('normal')
            records={'commands':[self.record('Clear-History')],'command_coverage':[]}
            alerts=analyze(records['commands']);component={'name':'command fixture','status':'completed','records':1}
            events=[]
            with patch('atlasac.systemscan.collect_command_traces',return_value=(records,alerts,component)),patch('atlasac.systemscan.collect_system',return_value=({'processes':[]},[])):
                report=system_scan(load_rules(RULES),[root],data_dir=Path(tmp)/'state',artifacts=True,progress=events.append)
            early=next(e for e in events if e.get('new_findings'))
            self.assertEqual(early['indexed'],0)
            self.assertEqual(report['findings'][0]['rule'],'history-clear-command')
            self.assertEqual(report['artifacts']['commands'],records['commands'])
            self.assertEqual(sum('artifact_snapshot' in e for e in events),1)

    def test_native_windows_output_decodes_utf16_errors_and_utf8(self):
        from atlasac.commandtraces import decode_windows_text
        for encoding in ('utf-16','utf-16-le','utf-8'):
            self.assertEqual(decode_windows_text('Access denied'.encode(encoding)),'Access denied')
