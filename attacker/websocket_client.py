import argparse,asyncio
from pathlib import Path
import websockets
p=argparse.ArgumentParser(); p.add_argument("--url",required=True); p.add_argument("--file",required=True); a=p.parse_args()
async def m():
    async with websockets.connect(a.url) as w:
        await w.send(Path(a.file).read_bytes())
        await w.recv()
loop=asyncio.get_event_loop()
loop.run_until_complete(m())
loop.close()
