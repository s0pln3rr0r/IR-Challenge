from pathlib import Path
import qrcode
o=Path(__file__).resolve().parent.parent/"runtime"/"qr"; o.mkdir(parents=True,exist_ok=True)
for n,v in [("IMG_1841.png","Hnc"),("IMG_1842.png","fuEY"),("IMG_1843.png","92kL")]:
    qrcode.make(v).save(o/n)
