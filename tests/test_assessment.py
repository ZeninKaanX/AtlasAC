import unittest
from pathlib import Path
from atlasac.assessment import classify,name_context,process_context
from atlasac.methodcoverage import coverage,METHODS
from atlasac.reveal import verdict_for,GLYPHS

class AssessmentTests(unittest.TestCase):
    def test_static_identity_never_proves_game_use(self):
        for method,level in [('file-sha256','exact-file'),('mod-id','declared-metadata'),('class-signature','class-layout'),('sha256','local-hash')]:
            row=classify([{'method':method}])[0]
            self.assertEqual(row['evidence_level'],level);self.assertFalse(row['usage_proven']);self.assertEqual(row['active_features'],'not-established')

    def test_normal_java_agent_macro_and_turkish_letters_are_context_only(self):
        rows=[{'name':'java.exe','pid':1,'cmdline':['java','-javaagent:accessibility.jar','--gameDir','/mods']},{'name':'AutoHotkey64.exe','pid':2,'cmdline':['AutoHotkey64.exe','accessibility.ahk']}]
        result=process_context(rows)
        self.assertEqual(len(result['jvm_context']),1);self.assertEqual(len(result['macro_context']),1)
        self.assertFalse(result['macro_context'][0]['usage_proven'])
        self.assertIsNone(name_context(Path('Türkçe-oyun.jar')))
        context=name_context(Path('client\u202e.jar'));self.assertEqual(context['classification'],'filename-context');self.assertFalse(context['usage_proven'])

    def test_all_50_methods_report_actual_gaps(self):
        rows=coverage({'artifacts':{'services':[]}},platform='windows')
        self.assertEqual([r['method_id'] for r in rows],[f'M{i:02}' for i in range(1,51)])
        self.assertEqual(rows[6]['collection_status'],'unsupported')
        self.assertEqual(rows[16]['capability'],'inventory-only')
        self.assertEqual(rows[16]['collection_status'],'no-records')
        self.assertEqual(coverage({},platform='linux')[10]['collection_status'],'not-applicable')

    def test_context_signal_is_amber_review_not_cheat_or_clean(self):
        report={'status':'completed','findings':[],'artifacts':{'review_signals':[{'rule':'history-clear-command'}]}}
        title,detail,color=verdict_for(report);self.assertEqual(title,'İnceleme');self.assertNotEqual(color,'#ed2639')
        self.assertTrue(all(c in GLYPHS for c in title))
        report['status']='partial';self.assertIn('tamamlanmadı',verdict_for(report)[1])
