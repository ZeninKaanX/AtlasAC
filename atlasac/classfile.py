"""Bounded Java constant-pool reader. No bytecode is executed or loaded into a JVM."""
import struct


def references(data):
    if len(data)<10 or data[:4]!=b'\xca\xfe\xba\xbe':
        raise ValueError('Geçersiz Java class başlığı')
    count=struct.unpack_from('>H',data,8)[0]
    if count<1:raise ValueError('Geçersiz constant-pool boyutu')
    cp=[None]*count;pos=10;i=1
    def take(n):
        nonlocal pos
        if pos+n>len(data):raise ValueError('Kesik Java constant-pool')
        result=data[pos:pos+n];pos+=n;return result
    while i<count:
        tag=take(1)[0]
        if tag==1:
            length=int.from_bytes(take(2),'big');cp[i]=(tag,take(length).decode('utf-8',errors='replace'))
        elif tag in (3,4):take(4)
        elif tag in (5,6):take(8);i+=1
        elif tag in (7,8,16,19,20):cp[i]=(tag,int.from_bytes(take(2),'big'))
        elif tag in (9,10,11,12,17,18):cp[i]=(tag,int.from_bytes(take(2),'big'),int.from_bytes(take(2),'big'))
        elif tag==15:take(3)
        else:raise ValueError(f'Desteklenmeyen constant-pool etiketi: {tag}')
        i+=1
    def item(index,tag):
        if not 0<index<count or cp[index] is None or cp[index][0]!=tag:
            raise ValueError('Geçersiz Java constant-pool başvurusu')
        return cp[index]
    def text(index):return item(index,1)[1]
    methods=set();strings=set()
    for entry in cp:
        if entry is None:continue
        if entry[0]==8:strings.add(text(entry[1]))
        if entry[0] in (10,11):
            owner=text(item(entry[1],7)[1]);nt=item(entry[2],12)
            methods.add((owner,text(nt[1]),text(nt[2])))
    return strings,methods



def known_chat_backdoor(strings, methods):
    """A fingerprint validated against four modified public Bukkit plugins.

    This is static evidence of the known pattern, never proof it ran.
    """
    pairs={(owner,name) for owner,name,_ in methods}
    required={('org/bukkit/Server','dispatchCommand'),
              ('org/bukkit/Server','getConsoleSender'),
              ('org/bukkit/event/player/AsyncPlayerChatEvent','getMessage')}
    return 'hacktheserver' in strings and required.issubset(pairs)
