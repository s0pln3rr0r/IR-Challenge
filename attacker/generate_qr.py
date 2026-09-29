from pathlib import Path
import qrcode
import os
o=Path(__file__).resolve().parent.parent/"runtime"/"qr"
try: o.mkdir(parents=True)
except FileExistsError: pass
for n,v in [("IMG_1841.png","Hnc"),("IMG_1842.png","fuEY"),("IMG_1843.png","92kL")]:
    qrcode.make(v).save(str(o/n))
