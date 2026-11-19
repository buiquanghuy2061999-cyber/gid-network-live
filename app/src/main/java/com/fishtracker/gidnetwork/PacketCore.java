package com.fishtracker.gidnetwork;

import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * PCAPdroid UDP Exporter -> classic PCAP records -> IPv4/TCP -> 2E game frames.
 * Pure Java and strictly observational. Never transmits, modifies, or replays a game packet.
 * No FishID decoder is implemented: encrypted-looking payload MUST NOT be guessed as FishID.
 */
public final class PacketCore {
    public interface Listener { void event(String event); }
    private final Listener listener;
    public long packets = 0, tcpPackets = 0, frames = 0, upFrames = 0, downFrames = 0;
    private final Map<String, Stream> streams = new HashMap<>();
    private int linkType = 101; // LINKTYPE_RAW, PCAPdroid default without extensions
    private final ArrayDeque<TimedLength> down = new ArrayDeque<>();
    private final ArrayDeque<Long> recent38Up = new ArrayDeque<>();
    public static final int LISTEN_PORT = 5123;
    public static final int GAME_PORT = 3341;
    public static final int GAME_PORT_ALT = 3331; // observed in 2026-11-19 full-login capture
    public long simple2fFrames = 0;

    public PacketCore(Listener listener) { this.listener = listener; }
    private static int u8(byte[] b, int n) { return b[n] & 255; }
    private static int be16(byte[] b, int off) { return (u8(b,off)<<8) | u8(b,off+1); }
    private static long be32(byte[] b,int off) { return ((long)u8(b,off)<<24) | ((long)u8(b,off+1)<<16) | ((long)u8(b,off+2)<<8) | u8(b,off+3); }
    private static long le32(byte[] b,int off) { return (u8(b,off) & 255L) | ((long)u8(b,off+1)<<8) | ((long)u8(b,off+2)<<16) | ((long)u8(b,off+3)<<24); }

    /** Receives an entire *UDP datagram* from PCAPdroid, not a raw TCP payload. */
    public synchronized void acceptDatagram(byte[] data, int size, long wallClockMs) {
        if(size < 16) return;
        // Classic PCAP global header, emitted when exporter starts.
        if (size == 24 && u8(data,0)==0xd4 && u8(data,1)==0xc3 && u8(data,2)==0xb2 && u8(data,3)==0xa1) {
            linkType = (int)le32(data,20);
            streams.clear(); down.clear(); recent38Up.clear(); lastBurstAt=-1; lastCastBurstAt=-1; repeatedBurstCandidates=0; castBurstCandidates=0; simple2fFrames=0;
            listener.event("Nhận header PCAP (linktype=" + linkType + ")");
            return;
        }
        // PCAP per-packet header (little endian), followed by IP packet.
        int capLen = (int)le32(data,8);
        if (capLen <= 0 || capLen > size-16 || capLen > 65535) return;
        packets++;
        int off=16;
        if (linkType == 1) { // Ethernet (for compatibility; extensions disabled in API request)
            if (capLen < 14 || be16(data,off+12) != 0x0800) return;
            off += 14;
        } else if (linkType != 101) return;
        parseIpv4(data,off,16+capLen,wallClockMs);
    }
    private void parseIpv4(byte[] b,int off,int end,long now) {
        if(end-off < 40 || (u8(b,off)>>4)!=4) return;
        int ipHeader=(u8(b,off)&15)*4;
        int length=be16(b,off+2);
        if(ipHeader<20 || length<ipHeader+20 || off+length>end || u8(b,off+9)!=6) return;
        // Skip fragmented IP packets, rather than misparse incomplete TCP segment.
        if((be16(b,off+6)&0x3fff)!=0) return;
        int tcpOff=off+ipHeader;
        int srcPort=be16(b,tcpOff), dstPort=be16(b,tcpOff+2);
        if (srcPort!=GAME_PORT && dstPort!=GAME_PORT && srcPort!=GAME_PORT_ALT && dstPort!=GAME_PORT_ALT) return;
        int tcpHeader=((u8(b,tcpOff+12)>>4)&15)*4;
        if(tcpHeader<20 || ipHeader+tcpHeader>length) return;
        int payOff=tcpOff+tcpHeader;
        int payLen=off+length-payOff;
        if(payLen<=0) return;
        tcpPackets++;
        boolean upload=(dstPort==GAME_PORT || dstPort==GAME_PORT_ALT);
        long seq=be32(b,tcpOff+4);
        String key=ip(b,off+12)+":"+srcPort+">"+ip(b,off+16)+":"+dstPort;
        Stream s=streams.get(key);
        if (s==null) { s=new Stream(upload); streams.put(key,s); }
        s.accept(seq,Arrays.copyOfRange(b,payOff,payOff+payLen),now);
    }
    private static String ip(byte[] b,int off){ return u8(b,off)+"."+u8(b,off+1)+"."+u8(b,off+2)+"."+u8(b,off+3); }
    // Strictly metadata-only detection: the 38-byte requests are too common to imply fishing.
    // A large 32x70 group with 150/278/1094 frames appeared three times in the
    // user's full-session capture. This is a traffic burst, NOT a decoded fish event.
    public long repeatedBurstCandidates = 0;
    /** Correlated send-38B + 20+ reply-70B: candidate cast event, not verified FishID. */
    public long castBurstCandidates = 0;
    private long lastCastBurstAt = -1;
    private long lastBurstAt = -1;
    private void onGameFrame(boolean upload,int length,long now,boolean simple2f){
        frames++;
        if(upload)upFrames++;else downFrames++;
        if(simple2f){
            simple2fFrames++;
            listener.event("Đã nhận khung 2F; FishID chưa giải mã");
            return;
        }
        if(upload) {
            if(length==38) {
                recent38Up.addLast(now);
                while(!recent38Up.isEmpty() && now-recent38Up.peekFirst()>2000)recent38Up.removeFirst();
            }
            return;
        }
        down.addLast(new TimedLength(length, now));
        while(!down.isEmpty() && now-down.peekFirst().at>950)down.removeFirst();
        while(!recent38Up.isEmpty() && now-recent38Up.peekFirst()>2000)recent38Up.removeFirst();
        // From five independent captures: each of six large 70B bursts follows a 38B
        // upstream frame by 100-190ms, while the idle control has zero such bursts.
        // This recognizes *candidate casts*, INCLUDING failed catches; never a FishID.
        if(length==70 && (lastCastBurstAt<0 || now-lastCastBurstAt>=3000)){
            for(Long sentAt: recent38Up){
                long delta=now-sentAt;
                if(delta<50 || delta>450)continue;
                int n=0;
                for(TimedLength item:down){
                    if(item.len==70 && item.at-sentAt>=50 && item.at-sentAt<=450)n++;
                }
                if(n>=20){
                    castBurstCandidates++;
                    lastCastBurstAt=now;
                    listener.event("Ứng viên thả câu: gói gửi 38B → " + n + " khung nhận 70B; FishID chưa giải mã");
                    break;
                }
            }
        }
        if(lastBurstAt>=0 && now-lastBurstAt<4000)return;
        int n70=0;boolean a150=false,a278=false,a1094=false;
        for(TimedLength d:down){
            if(d.len==70)n70++;
            if(d.len==150)a150=true;
            if(d.len==278)a278=true;
            if(d.len==1094)a1094=true;
        }
        if(n70>=32 && a150 && a278 && a1094){
            lastBurstAt=now;repeatedBurstCandidates++;
            // Kept as a secondary diagnostic counter; avoid duplicate user alerts.
        }
    }
    private static final class TimedLength { final int len; final long at; TimedLength(int l,long a){len=l;at=a;} }
    private final class Stream {
        final boolean up;
        long nextSeq=-1;
        final TreeMap<Long,byte[]> ahead=new TreeMap<>();
        byte[] bytes=new byte[262144]; int filled=0;
        Stream(boolean u){up=u;}
        void accept(long seq,byte[] data,long now){
            if(nextSeq<0) nextSeq=seq;
            if(seq>nextSeq){
                if(ahead.size()<128 && seq-nextSeq<131072) ahead.put(seq,data);
                return;
            }
            appendSegment(seq,data,now);
            while(!ahead.isEmpty()){
                Map.Entry<Long,byte[]> e=ahead.firstEntry();
                if(e.getKey()>nextSeq)break;
                ahead.pollFirstEntry();appendSegment(e.getKey(),e.getValue(),now);
            }
        }
        void appendSegment(long seq,byte[] data,long now){
            long overlap=nextSeq-seq;
            if(overlap>=data.length)return;
            int offset=(int)Math.max(0,overlap);
            int count=data.length-offset;
            nextSeq+=count;
            if(filled+count>bytes.length){filled=0; listener.event("Tràn bộ đệm TCP, đặt lại khung đang đọc");}
            System.arraycopy(data,offset,bytes,filled,count);
            filled+=count;
            parseFrames(now);
        }
        void parseFrames(long now){
            int pos=0;
            while(filled-pos>=6){
                if(u8(bytes,pos)!=0x32 || (u8(bytes,pos+1)!=0x45 && u8(bytes,pos+1)!=0x46)){pos++;continue;}
                long n=be32(bytes,pos+2);
                // Frame header '2E', total length including 6-byte header. Our captures suggest n % 16 == 6.
                boolean simple2f=(u8(bytes,pos+1)==0x46);
                if(n<10 || n>bytes.length || (simple2f ? (n-6)%4!=0 : n%16!=6)){pos++;continue;}
                if(filled-pos<n)break;
                onGameFrame(up,(int)n,now,simple2f);
                pos+=(int)n;
            }
            if(pos>0){
                System.arraycopy(bytes,pos,bytes,0,filled-pos);
                filled-=pos;
            }
        }
    }
}
