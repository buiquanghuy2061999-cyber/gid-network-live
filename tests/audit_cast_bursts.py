#!/usr/bin/env python3
"""Read-only/metadata-only burst audit over user-supplied PCAP files.
Never prints packet contents, key material, messages or account fields.
Requires offline_analyze_pcap.py alongside this script; Python standard library.
Example: python tests/audit_cast_bursts.py /path/to/PCAPdroid_*.pcap
"""
import collections
import csv
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import offline_analyze_pcap as a

def audit(path):
    selected=None
    for port in (3331,3341):
        a.TARGET_PORT=port
        rows, t0, t1=a.read_pcap(path)
        if not rows:continue
        try:
            frames=sum((a.parse_frames(f,t0) for f in a.assemble(rows)),[])
        except ValueError:
            continue
        if not frames:continue
        if selected is None or len(frames)>len(selected[1]):selected=(port,frames)
    if selected is None:return [],0,None
    port,frames=selected
    sends=sorted(f['time_s'] for f in frames if f['direction']=='up' and f['frame_len']==38 and f['frame_magic']=='2E')
    recvs=sorted(f['time_s'] for f in frames if f['direction']=='down' and f['frame_len']==70 and f['frame_magic']=='2E')
    hits=[];last=-float('inf')
    for sent in sends:
        after=[r for r in recvs if 0.05<=r-sent<=0.45]
        if len(after)>=20 and sent-last>3:
            hits.append({'file':Path(path).name, 'port':port, 'request_s':round(sent,4),
                         'first_response_s':round(after[0],4), 'latency_ms':round((after[0]-sent)*1000),
                         'responses_70B':len(after), 'fishid':'UNVERIFIED'})
            last=sent
    return hits,len(frames),port

def main():
    all_hits=[];total_frames=0
    print('File, Port, Frames, Candidate casts')
    for p in map(Path,sys.argv[1:]):
        hits,n,port=audit(p)
        print(p.name,port,n,len(hits))
        total_frames+=n;all_hits+=hits
    print('TOTAL',total_frames,'frames and',len(all_hits),'candidate casts')
    for row in all_hits:print(row)
if __name__=='__main__':main()
