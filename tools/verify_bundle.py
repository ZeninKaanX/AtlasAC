"""Verify bundled trusted code against source, ignoring compiler filename metadata."""
import hashlib,marshal,sys,types
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader

def signature(code):
    def value(item):
        if isinstance(item,types.CodeType):return ('code',signature(item))
        if isinstance(item,tuple):return tuple(value(x) for x in item)
        if isinstance(item,frozenset):return ('frozenset',sorted(map(repr,item)))
        return item
    return (code.co_code,code.co_names,code.co_varnames,code.co_freevars,code.co_cellvars,
            code.co_flags,code.co_argcount,code.co_posonlyargcount,code.co_kwonlyargcount,
            tuple(value(c) for c in code.co_consts))

def verify(path):
    archive=CArchiveReader(str(path))
    embedded=archive.open_embedded_archive(next(k for k in archive.toc if k.endswith('.pyz')))
    for module in ('audit','privacy','securestore','reports','assessment','methodcoverage','commandtraces','cpubudget','pixels','contentcache','findingicons','desktop','widgets','reveal','filepolicy','scope','scanprocess','fileprobe','systemscan','index','collectors','winrecords','engine','__main__'):
        file=Path('atlasac')/(module+'.py')
        expected=compile(file.read_bytes(),str(file),'exec',dont_inherit=True)
        actual=embedded.extract('atlasac.'+module)
        assert signature(actual)==signature(expected),f'{path}: stale module {module}'
    for name in ('atlasac/web/assets/atlasac-mobile-transparent.png','atlasac/web/assets/atlasoyuncu-background.gif','rules/default.json','atlasac/web/assets/reveal-timing.json','atlasac/web/assets/reveal.wav','atlasac/web/assets/shark.png','atlasac/web/assets/fish.png','atlasac/web/assets/minecraft-clownfish.png','atlasac/web/assets/minecraft-shark.png'):
        key=next(k for k in archive.toc if k.replace('\\','/')==name)
        assert archive.extract(key)==Path(name).read_bytes(),name
    for file in Path('atlasac/web/assets/client-icons').glob('*.png'):
        key=next(k for k in archive.toc if k.replace('\\','/')==file.as_posix())
        assert archive.extract(key)==file.read_bytes(),str(file)
    assert not any('WebEngine' in k for k in archive.toc)
    print(path,': current code and assets verified')

if __name__=='__main__':
    for path in sys.argv[1:]:verify(path)
