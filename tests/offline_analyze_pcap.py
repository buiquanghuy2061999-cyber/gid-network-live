#!/usr/bin/env python3
"""Offline read-only parser for PCAPdroid RAW-IP pcap with custom 2E frames.
No third party dependencies. No decryption, proxy, injection or game interaction.
Usage: python analyze_pcap.py /path/to/*.pcap --out report_dir
"""
import argparse
import collections
import csv
import glob
import json
import math
import os
import struct
from pathlib import Path

TARGET_IP = "118.26.111.64"
TARGET_PORT = 3341
MAGICS = (b'2E', b'2F')  # two native client transport families


def read_pcap(path):
    contents = Path(path).read_bytes()
    mag = contents[:4]
    settings = {b'\xd4\xc3\xb2\xa1': ('<',1e6), b'\xa1\xb2\xc3\xd4': ('>',1e6),
                b'\x4d\x3c\xb2\xa1': ('<',1e9), b'\xa1\xb2\x3c\x4d': ('>',1e9)}
    if mag not in settings:
        raise ValueError('Unsupported PCAP magic (only classic pcap)')
    endian, divisor = settings[mag]
    if len(contents) < 24:
        raise ValueError('Truncated global header')
    linktype = struct.unpack_from(endian+'I',contents,20)[0]
    if linktype != 101:
        raise ValueError('Expected PCAPdroid RAW IPv4 (DLT 101); got '+str(linktype))
    p = 24
    records = []
    first_timestamp = None
    last_timestamp = None
    while p+16 <= len(contents):
        sec, subsecs, inclen, origlen = struct.unpack_from(endian+'IIII',contents,p)
        p += 16
        if p+inclen > len(contents):
            raise ValueError('Truncated PCAP packet')
        packet=contents[p:p+inclen]
        p+=inclen
        ts=sec+subsecs/divisor
        if first_timestamp is None:first_timestamp=ts
        last_timestamp=ts
        if len(packet) < 20 or (packet[0]>>4)!=4:
            continue
        ihl=(packet[0]&15)*4
        if ihl<20 or len(packet)<ihl+20 or packet[9]!=6:
            continue
        iplen=struct.unpack_from('!H',packet,2)[0]
        packet=packet[:iplen]
        sp,dp,seq,ack=struct.unpack_from('!HHII',packet,ihl)
        tcp_header=(packet[ihl+12]>>4)*4
        if tcp_header<20 or len(packet)<ihl+tcp_header:continue
        dat=packet[ihl+tcp_header:]
        src='.'.join(str(x) for x in packet[12:16]);dst='.'.join(str(x) for x in packet[16:20])
        if TARGET_IP not in (src,dst) or TARGET_PORT not in (sp,dp):
            continue
        records.append({'ts':ts,'src':src,'dst':dst,'sport':sp,
                        'dport':dp,'seq':seq,'payload':dat})
    return records, first_timestamp, last_timestamp


def assemble(records):
    flows=collections.defaultdict(list)
    for r in records:
        if r['payload']:
            key=(r['src'],r['sport'],r['dst'],r['dport'])
            flows[key].append(r)
    out=[]
    for key,packets in flows.items():
        base=min(r['seq'] for r in packets)
        end=max(r['seq']+len(r['payload']) for r in packets)
        if end-base>100_000_000:
            raise ValueError('TCP sequence gap too large (possibly sequence wrap)')
        stream=bytearray(end-base);mask=bytearray(end-base);conflicts=0
        for r in sorted(packets,key=lambda t:t['ts']):
            offset=r['seq']-base
            for j,b in enumerate(r['payload']):
                if mask[offset+j] and stream[offset+j]!=b:
                    conflicts+=1
                stream[offset+j]=b;mask[offset+j]=1
        if any(v==0 for v in mask):
            raise ValueError(f'Missing TCP payload bytes for {key}; cannot safely parse frames')
        if conflicts:
            raise ValueError(f'Overlapping retransmissions disagree in {key}')
        out.append({'key':key,'packets':packets,'data':bytes(stream),'base_seq':base})
    return out


def parse_frames(flow,t0):
    blob=flow['data'];index=0;frames=[]
    while index<len(blob):
        if len(blob)-index<6 or blob[index:index+2] not in MAGICS:
            raise ValueError(f'Unexpected frame header at stream offset {index}')
        n=int.from_bytes(blob[index+2:index+6],'big')
        if n<6 or n>len(blob)-index:
            raise ValueError(f'Invalid/incomplete frame len {n} at offset {index}')
        payload=blob[index+6:index+n]
        seq=flow['base_seq']+index
        ts=min((r['ts'] for r in flow['packets'] if r['seq']<=seq<r['seq']+len(r['payload'])),default=None)
        direction='up' if flow['key'][3]==TARGET_PORT else 'down'
        frames.append({'frame_magic':blob[index:index+2].decode('ascii'), 'direction':direction,'time_s':round(ts-t0,4) if ts else None,
                       'stream_offset':index,'frame_len':n,'payload_len':n-6,
                       'blocks_16':(n-6)//16,'payload':payload})
        index+=n
    return frames


def entropy(data):
    if not data:return 0.
    freq=collections.Counter(data);length=len(data)
    return -sum(c/length*math.log2(c/length) for c in freq.values())


def load_fishids(path):
    if not path:return set()
    obj=json.loads(Path(path).read_text(encoding='utf8'))
    return set(int(r['FishID']) for r in obj['records'])


def scan_id(frames,known):
    # Matches only; any matches may be coincidental and MUST NOT be called decoded IDs.
    matches=[]
    for f in frames:
        body=f['payload']
        for i in range(len(body)-3):
            b=body[i:i+4]
            for order in ('little','big'):
                value=int.from_bytes(b,order)
                if value in known:
                    matches.append({'direction':f['direction'],'frame_len':f['frame_len'],
                                    'time_s':f['time_s'],'payload_offset':i,'integer':value,'byte_order':order})
    return matches


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('pcaps',nargs='+',help='PCAP filenames or glob expressions')
    ap.add_argument('--out',default='gid_pcap_results',help='Output folder')
    ap.add_argument('--fishids',help='Optional local FishID_429_Game164_Lookup.json')
    args=ap.parse_args()
    paths=sorted({p for term in args.pcaps for p in glob.glob(term)})
    if not paths:ap.error('No PCAP files matched')
    known=load_fishids(args.fishids)
    out=Path(args.out);out.mkdir(exist_ok=True,parents=True)
    rows=[];summaries=[];allblocks=[];id_matches=[]
    for path in paths:
        packets,start,last=read_pcap(path)
        if not packets:continue
        fs=[]
        for flow in assemble(packets):fs.extend(parse_frames(flow,start))
        fs.sort(key=lambda x:(x['time_s'],x['direction'],x['stream_offset']))
        for f in fs:
            rows.append({k:f[k] for k in ('direction','time_s','stream_offset','frame_len','payload_len','blocks_16')} | {'capture':Path(path).stem})
            for i in range(0,len(f['payload']),16):allblocks.append(f['payload'][i:i+16])
        client=[f for f in fs if f['direction']=='up']
        server=[f for f in fs if f['direction']=='down']
        for item in scan_id(fs,known):item['capture']=Path(path).stem;id_matches.append(item)
        summary={'capture':Path(path).stem,
                 'duration_s':round(last-start,3),
                 'client_frames':len(client),'server_frames':len(server),
                 'client_bytes':sum(f['frame_len'] for f in client),
                 'server_bytes':sum(f['frame_len'] for f in server),
                 'client_38_times_s':[f['time_s'] for f in client if f['frame_len']==38],
                 'all_lengths_mod16_equal6':all(f['frame_len']%16==6 for f in fs),
                 'server_len_histogram':dict(sorted(collections.Counter(f['frame_len'] for f in server).items()))}
        summaries.append(summary)
    with (out/'frames.csv').open('w',encoding='utf-8',newline='') as fout:
        w=csv.DictWriter(fout,fieldnames=['capture','direction','time_s','stream_offset','frame_len','payload_len','blocks_16'])
        w.writeheader();w.writerows(rows)
    metadata={'captures':summaries,'total_frames':len(rows),'total_16byte_blocks':len(allblocks),
              'unique_16byte_blocks':len(set(allblocks)),
              'fishid_scan':{'known_ids':len(known),'four_byte_candidate_matches':id_matches,
                             'warning':'Numerical matches in encrypted-looking bytes are not decoded IDs'}}
    (out/'summary.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf8')
    if known:
        with (out/'fishid_fourbyte_matches.csv').open('w',encoding='utf-8',newline='') as fout:
            w=csv.DictWriter(fout,fieldnames=['capture','direction','time_s','frame_len','payload_offset','integer','byte_order'])
            w.writeheader();w.writerows(id_matches)
    print('Parsed',len(rows),'frames from',len(summaries),'captures')
    print('All frame lengths = 6 mod 16:',all(s['all_lengths_mod16_equal6'] for s in summaries))
    print('16-byte blocks',len(allblocks),'unique',len(set(allblocks)))
    print('Results in',out)

if __name__=='__main__':main()
