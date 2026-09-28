import asyncio
from pathlib import Path
import websockets
out=Path(__file__).resolve().parent.parent/"runtime"/"received"; out.mkdir(parents=True,exist_ok=True)
async def h(ws):
    d=await ws.recv()
    (out/"websocket_payload").write_bytes(d if isinstance(d,bytes) else d.encode())
    await ws.send("OK")
async def main():
    async with websockets.serve(h,"0.0.0.0",8080): await asyncio.Future()
asyncio.run(main())
