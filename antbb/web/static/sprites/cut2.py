from PIL import Image
import numpy as np
from collections import deque
MAP={'queen_sheet.png':'queen','b.png':'worker','c.png':'soldier_def','d.png':'soldier_off','scout_sheet.png':'scout'}
def floodbg(im, tol=38):
    im=im.convert('RGBA'); a=np.array(im); h,w=a.shape[:2]
    rgb=a[:,:,:3].astype(int)
    seen=np.zeros((h,w),bool)
    dq=deque()
    corners=[(0,0),(0,w-1),(h-1,0),(h-1,w-1)]
    for (y,x) in corners:
        cref=rgb[y,x]
        if not seen[y,x]:
            seen[y,x]=True; dq.append((y,x,tuple(cref)))
    # multi-source flood using each pixel's own ref? simpler: global ref = median of border
    border=np.concatenate([rgb[0,:],rgb[-1,:],rgb[:,0],rgb[:,-1]])
    ref=np.median(border,axis=0)
    seen[:]=False
    dq=deque()
    for (y,x) in corners:
        seen[y,x]=True; dq.append((y,x))
    def near(y,x):
        return abs(int(rgb[y,x,0])-ref[0])+abs(int(rgb[y,x,1])-ref[1])+abs(int(rgb[y,x,2])-ref[2])<tol*3
    while dq:
        y,x=dq.popleft()
        if not near(y,x): continue
        a[y,x,3]=0
        for dy,dx in((1,0),(-1,0),(0,1),(0,-1)):
            ny,nx=y+dy,x+dx
            if 0<=ny<h and 0<=nx<w and not seen[ny,nx]:
                seen[ny,nx]=True; dq.append((ny,nx))
    return Image.fromarray(a,'RGBA')
def autocrop(im):
    bb=im.getbbox(); return im.crop(bb) if bb else im
for sheet,name in MAP.items():
    im=Image.open('refs/'+sheet).convert('RGBA'); W,H=im.size
    top=int(H*0.11); bot=int(H*0.90); pw=W//4
    for idx,tag in[(0,'front'),(3,'tq')]:
        # trim 5% inner margins to drop neighbor bleed
        x0=int(idx*pw+pw*0.04); x1=int((idx+1)*pw-pw*0.04)
        panel=im.crop((x0,top,x1,bot))
        panel=floodbg(panel)
        panel=autocrop(panel)
        panel.save(f'{name}_{tag}.png'); print(f'{name}_{tag}',panel.size)
