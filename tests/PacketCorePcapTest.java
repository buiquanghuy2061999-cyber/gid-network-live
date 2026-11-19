import com.fishtracker.gidnetwork.PacketCore;
import java.io.*;
import java.nio.file.*;
import java.util.*;
/** JVM smoke test: feed real user PCAP records into exactly the same parser used by the app. */
public class PacketCorePcapTest {
    static int u8(byte[] b,int i){return b[i]&255;}
    static int le32(byte[] b,int o){return u8(b,o)|(u8(b,o+1)<<8)|(u8(b,o+2)<<16)|(u8(b,o+3)<<24);}
    public static void main(String[] args)throws Exception{
        long grand=0;
        for(String arg:args){
            byte[] p=Files.readAllBytes(Paths.get(arg));
            if(p.length<24 || u8(p,0)!=0xd4 || u8(p,1)!=0xc3)throw new IllegalArgumentException("Expected little endian PCAP");
            List<String> events=new ArrayList<>();
            PacketCore core=new PacketCore(events::add);
            core.acceptDatagram(Arrays.copyOfRange(p,0,24),24,System.currentTimeMillis());
            int i=24;
            while(i+16<=p.length){
                int incl=le32(p,i+8); if(incl<0||i+16+incl>p.length)throw new IllegalArgumentException("truncated");
                int sec=le32(p,i),usec=le32(p,i+4);
                long time=(sec&0xffffffffL)*1000+(usec&0xffffffffL)/1000;
                core.acceptDatagram(Arrays.copyOfRange(p,i,i+16+incl),16+incl,time);
                i+=16+incl;
            }
            System.out.printf("%s: total %d, up %d, down %d, 2F %d, castCandidates %d, events %d%n",arg,core.frames,core.upFrames,core.downFrames,core.simple2fFrames,core.castBurstCandidates,events.size());
            if(arg.contains("16_30_37") && (core.frames!=619 || core.simple2fFrames!=1 || core.repeatedBurstCandidates!=3 || core.castBurstCandidates!=3)) throw new AssertionError("Full login PCAP expected 619 frames incl one 2F and 3 bursts, got "+core.frames+"/"+core.simple2fFrames+"/"+core.repeatedBurstCandidates);
            int wanted=arg.contains("11_11_35")?0:arg.contains("16_30_37")?3:1;
            if(core.castBurstCandidates!=wanted)throw new AssertionError("Expected "+wanted+" candidate casts, got "+core.castBurstCandidates+" in "+arg);
            for(String ev:events)System.out.println("  "+ev);
            grand+=core.frames;
        }
        System.out.println("Total frames="+grand);
        if(args.length==4 && grand!=513)throw new AssertionError("Expected 513 frames across four provided PCAPs; got "+grand);
    }
}
