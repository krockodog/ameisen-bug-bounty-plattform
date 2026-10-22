from PIL import Image
import os
MAP = {
 'queen_sheet.png':'queen',
 'b.png':'worker',
 'c.png':'soldier_def',
 'd.png':'soldier_off',
 'scout_sheet.png':'scout',
}
# panel index 0=VORNE(front),3=DREIVIERTEL(3q)
def bg_to_alpha(im):
    im=im.convert('RGBA'); px=im.load(); w,h=im.size
    for y in range(h):
        for x in range(w):
            r,g,b,a=px[x,y]
            mx,mn=max(r,g,b),min(r,g,b)
            if r>205 and g>205 and b>200 and (mx-mn)<22:
                px[x,y]=(r,g,b,0)
    return im
def autocrop(im):
    bb=im.getbbox()
    return im.crop(bb) if bb else im
for sheet,name in MAP.items():
    im=Image.open('refs/'+sheet).convert('RGBA')
    W,H=im.size
    # trim title band (~top 12%) and label band (~bottom 10%)
    top=int(H*0.11); bot=int(H*0.90)
    pw=W//4
    for idx,tag in [(0,'front'),(3,'tq')]:
        x0=idx*pw; x1=(idx+1)*pw
        panel=im.crop((x0,top,x1,bot))
        panel=bg_to_alpha(panel)
        panel=autocrop(panel)
        out=f'{name}_{tag}.png'
        panel.save(out)
        print(out, panel.size)
