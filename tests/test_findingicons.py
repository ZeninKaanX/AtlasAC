import base64,io,json,tempfile,threading,unittest,zipfile
from pathlib import Path
from atlasac.findingicons import embedded_icon
from atlasac.fileprobe import probe
from atlasac.engine import load_rules
from atlasac.paths import ASSETS,RULES

class IconTests(unittest.TestCase):
    def test_detected_archive_carries_its_actual_metadata_icon(self):
        icon=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGP4DwQACfsD/fteaysAAAAASUVORK5CYII=')
        # An explicit fixture tests the archive mechanism; this is not a real-cheat coverage claim.
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'fixture.jar'
            with zipfile.ZipFile(file,'w') as z:
                z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client','icon':'assets/client.png'}));z.writestr('assets/client.png',icon)
            result=probe(file,load_rules(RULES),threading.Event())
            self.assertEqual(len(result['findings']),1)
            self.assertEqual(base64.b64decode(result['findings'][0]['icon_png_base64']),icon)
    def test_missing_or_oversized_icon_falls_back(self):
        for content in (None,b'x'*600000):
            stream=io.BytesIO()
            with zipfile.ZipFile(stream,'w') as z:
                z.writestr('fabric.mod.json',json.dumps({'id':'meteor-client','icon':'icon.png'}))
                if content:z.writestr('icon.png',content)
            self.assertIsNone(embedded_icon(stream,'sample.jar'))
