#!/usr/bin/env python3
from dnslib.server import DNSServer,BaseResolver
from dnslib import RR,QTYPE,A
from pathlib import Path
import time,os
out=Path(os.environ.get("SIXWAYS_RUNTIME","./runtime"))/"received"; out.mkdir(parents=True,exist_ok=True)
class R(BaseResolver):
    def resolve(self,request,handler):
        q=str(request.q.qname).rstrip(".")
        with (out/"dns_queries.log").open("a") as f:f.write(f"{time.time():.6f}\t{q}\n")
        r=request.reply(); r.add_answer(RR(request.q.qname,QTYPE.A,rdata=A("203.0.113.53"),ttl=30)); return r
DNSServer(R(),port=53,address="0.0.0.0").start_thread()
print("DNS listening")
while True: time.sleep(3600)
