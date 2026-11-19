import com.fishtracker.gidnetwork.PacketCore;
import java.io.*;
import java.util.*;

public class SyntheticProtocolTest {
    private static void le32(byte[] b,int off,int v){for(int n=0;n<4;n++)b[off+n]=(byte)(v>>>(n*8));}
    private static void be16(byte[] b,int off,int v){b[off]=(byte)(v>>>8);b[off+1]=(byte)v;}
    private static void be32(byte[] b,int off,long v){for(int n=0;n<4;n++)b[off+n]=(byte)(v>>>((3-n)*8));}
    private static byte[] frame(int n) {
        byte[] f=new byte[n];f[0]=0x32;f[1]=0x45;be32(f,2,n);
        for(int i=6;i<n;i++)f[i]=(byte)(0x40 + (i%20));return f;
    }
    private static byte[] pcapRecord(boolean up,long seq,byte[] body){return pcapRecordPort(up,seq,body,3341);}
    private static byte[] pcapRecordPort(boolean up,long seq,byte[] body,int port){
        int ipLen=20+20+body.length;byte[] b=new byte[16+ipLen];
        le32(b,0,123);le32(b,4,0);le32(b,8,ipLen);le32(b,12,ipLen);
        int i=16; b[i]=0x45;be16(b,i+2,ipLen);b[i+8]=64;b[i+9]=6;
        byte[] client={10,0,0,5};byte[] server={118,26,111,64};
        System.arraycopy(up?client:server,0,b,i+12,4);
        System.arraycopy(up?server:client,0,b,i+16,4);
        int tcp=i+20;be16(b,tcp,up?43000:port);be16(b,tcp+2,up?port:43000);
        be32(b,tcp+4,seq);b[tcp+12]=0x50;
        System.arraycopy(body,0,b,tcp+20,body.length);return b;
    }
    public static void main(String[]args){
        List<String> events=new ArrayList<>();PacketCore core=new PacketCore(events::add);
        byte[] global=new byte[24];global[0]=(byte)0xd4;global[1]=(byte)0xc3;global[2]=(byte)0xb2;global[3]=(byte)0xa1;
        global[4]=2;global[6]=4;le32(global,16,65535);le32(global,20,101);
        core.acceptDatagram(global,24,1000);
        byte[] u=pcapRecord(true,100,frame(38));core.acceptDatagram(u,u.length,2000);
        byte[] d1=frame(38),d2=frame(54),d3=frame(38);
        byte[] joined=new byte[d1.length+d2.length+d3.length];
        System.arraycopy(d1,0,joined,0,d1.length);
        System.arraycopy(d2,0,joined,d1.length,d2.length);
        System.arraycopy(d3,0,joined,d1.length+d2.length,d3.length);
        // Deliberately split a game frame across TCP segments.
        int cut=17;
        byte[] a=pcapRecord(false,300,Arrays.copyOfRange(joined,0,cut));
        byte[] b=pcapRecord(false,300+cut,Arrays.copyOfRange(joined,cut,joined.length));
        core.acceptDatagram(a,a.length,2020);core.acceptDatagram(b,b.length,2070);
        // Replay same TCP segment - must NOT double-count.
        core.acceptDatagram(b,b.length,2080);
        if(core.frames!=4 || core.upFrames!=1 || core.downFrames!=3)throw new AssertionError("frame counts incorrect: "+core.frames);
        // Do not infer FishID or fishing event from generic 38->54->38 lengths.
        // Secondary game port and simple 2F frame: both must be processed.
        PacketCore secondary=new PacketCore(msg->{});
        secondary.acceptDatagram(global,24,1000);
        byte[] newPort=pcapRecordPort(true,10,frame(38),3331);
        secondary.acceptDatagram(newPort,newPort.length,1000);
        byte[] simple=new byte[398];simple[0]=0x32;simple[1]=0x46;be32(simple,2,398);
        byte[] simpleDown=pcapRecordPort(false,20,simple,3331);
        secondary.acceptDatagram(simpleDown,simpleDown.length,1010);
        if(secondary.frames!=2 || secondary.simple2fFrames!=1)throw new AssertionError("port 3331 or 2F failed");
        // Synthetic candidate cast: one 38-byte request followed by 20 70-byte responses.
        PacketCore positive=new PacketCore(msg->{});
        positive.acceptDatagram(global,24,1000);
        byte[] upCast=pcapRecord(true,400,frame(38));
        positive.acceptDatagram(upCast,upCast.length,5000);
        byte[] many=new byte[20*70];
        for(int k=0;k<20;k++)System.arraycopy(frame(70),0,many,k*70,70);
        byte[] downBurst=pcapRecord(false,2000,many);
        positive.acceptDatagram(downBurst,downBurst.length,5180);
        if(positive.castBurstCandidates!=1)throw new AssertionError("Failed to detect correlated 38B/70B burst");
        PacketCore control=new PacketCore(msg->{});
        control.acceptDatagram(global,24,1000);
        control.acceptDatagram(downBurst,downBurst.length,5180);
        if(control.castBurstCandidates!=0)throw new AssertionError("False cast without request");
        System.out.println("SyntheticProtocolTest PASS, TCP reassembly, retransmission, correlated cast bursts, idle-negative, ports 3331/3341, frames 2E/2F");
    }
}
