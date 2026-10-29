"""Analyze every decoded frame; stores timing/geometry, never the user's video frames."""
from pathlib import Path
import hashlib,json,sys
from PIL import Image

def analyze(folder,video,output):
    frames=[]
    for path in sorted(Path(folder).glob('frame-*.png')):
        im=Image.open(path).convert('RGB');w,h=im.size
        title=im.crop((0,0,w,145));glow=im.crop((0,145,w,h))
        def region(image,minimum):
            pixels=image.load();peak=image.getchannel('R').getextrema()[1]
            coords=[(x,y) for y in range(image.height) for x in range(image.width)
                    if pixels[x,y][0]>=max(minimum,peak*.15) and pixels[x,y][1]<pixels[x,y][0]*.6 and pixels[x,y][2]<pixels[x,y][0]*.6]
            if peak<6 or not coords:return 0,None
            return round(peak/255,5),[min(p[0] for p in coords),min(p[1] for p in coords),max(p[0] for p in coords)+1,max(p[1] for p in coords)+1]
        alpha,box=region(title,6);light,bounds=region(glow,8)
        if bounds:bounds=[bounds[0]/w,(bounds[1]+145)/h,bounds[2]/w,(bounds[3]+145)/h]
        frames.append({'text':alpha,'y':round(box[1]/h,5) if box else .16,'glow':light,'bounds':bounds})
    assert len(frames)==175
    result={'fps_num':30000,'fps_den':1001,'frame_count':len(frames),'duration_seconds':len(frames)*1001/30000,
            'reference_sha256':hashlib.sha256(Path(video).read_bytes()).hexdigest(),'frames':frames}
    Path(output).write_text(json.dumps(result,separators=(',',':'))+'\n')
    return result

if __name__=='__main__':analyze(*sys.argv[1:])
