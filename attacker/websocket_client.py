import argparse
import asyncio
import websockets

p = argparse.ArgumentParser()
p.add_argument("--url", required=True)
p.add_argument("--file", required=True)
a = p.parse_args()

@asyncio.coroutine
def m():
    w = yield from websockets.connect(a.url)
    yield from w.send(open(a.file, 'rb').read())
    yield from w.recv()
    yield from w.close()

loop = asyncio.get_event_loop()
loop.run_until_complete(m())
loop.close()
