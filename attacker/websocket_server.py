import asyncio
from pathlib import Path
import websockets

out = Path(__file__).resolve().parent.parent / "runtime" / "received"
try:
    out.mkdir(parents=True)
except FileExistsError:
    pass

@asyncio.coroutine
def h(ws):
    d = yield from ws.recv()
    data = d if isinstance(d, bytes) else d.encode()
    with open(str(out / "websocket_payload"), 'wb') as f:
        f.write(data)
    yield from ws.send("OK")

@asyncio.coroutine
def main():
    ws_server = yield from websockets.serve(h, "0.0.0.0", 8080)
    yield from asyncio.Future()

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
loop.close()
