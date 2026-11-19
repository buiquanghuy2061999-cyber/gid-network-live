package com.fishtracker.gidnetwork;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.WindowManager;
import android.widget.TextView;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/** Receives PCAPdroid's local UDP stream. Does not create a VPN, MITM, or transmit game data. */
public final class CaptureService extends Service {
    public static final String ACTION_STOP = "com.fishtracker.gidnetwork.STOP";
    public static final String ACTION_UPDATE = "com.fishtracker.gidnetwork.UPDATE";
    public static final String EXTRA_LOG = "log";
    public static final String EXTRA_STATS = "stats";
    public static final String PREFS = "gid_data";
    public static final String PREF_EVENTS = "event_log";
    private static final String CHANNEL="gid-network";
    private final AtomicBoolean running=new AtomicBoolean(false);
    private final Handler main=new Handler(Looper.getMainLooper());
    private volatile DatagramSocket socket;
    private volatile Thread worker;
    private PacketCore core;
    private WindowManager window;
    private TextView overlay;
    private long lastUi=0;
    private String lastEvent="Đang chờ gói tin của game";

    @Override public void onCreate(){
        super.onCreate();
        NotificationManager nm=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        if(Build.VERSION.SDK_INT>=26) nm.createNotificationChannel(new NotificationChannel(CHANNEL,"gid: giám sát mạng",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        if(intent!=null && ACTION_STOP.equals(intent.getAction())){
            shutdown();stopSelf();return START_NOT_STICKY;
        }
        if(running.get())return START_STICKY;
        startForeground(401, notification());
        running.set(true);
        core=new PacketCore(this::recordEvent);
        showOverlayIfAllowed();
        worker=new Thread(this::receiveLoop,"gid-udp-receiver"); worker.start();
        recordEvent("gid bắt đầu nhận luồng PCAPdroid tại 127.0.0.1:5123");
        return START_STICKY;
    }
    private Notification notification(){
        Intent go=new Intent(this,MainActivity.class);
        PendingIntent open=PendingIntent.getActivity(this,1,go,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        Intent stop=new Intent(this,CaptureService.class).setAction(ACTION_STOP);
        PendingIntent end=PendingIntent.getService(this,2,stop,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this,CHANNEL)
                .setContentTitle("gid đang nhận dữ liệu mạng")
                .setContentText("Chỉ đọc • FishID chưa giải mã")
                .setSmallIcon(android.R.drawable.ic_menu_search)
                .setContentIntent(open)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel,"Dừng gid",end)
                .setOngoing(true).build();
    }
    private void receiveLoop(){
        try(DatagramSocket s=new DatagramSocket(null)){
            s.setReuseAddress(true);
            s.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),PacketCore.LISTEN_PORT));
            socket=s;
            byte[] buf=new byte[65535];
            while(running.get()){
                DatagramPacket datagram=new DatagramPacket(buf,buf.length);
                s.receive(datagram);
                core.acceptDatagram(datagram.getData(),datagram.getLength(),System.currentTimeMillis());
                long now=System.currentTimeMillis();
                if(now-lastUi>900){lastUi=now;publish();}
            }
        }catch(SocketException ex){
            if(running.get())recordEvent("Lỗi cổng 5123: "+ex.getMessage());
        }catch(Exception ex){
            if(running.get())recordEvent("Không thể nhận UDP: "+ex.getClass().getSimpleName()+" / "+ex.getMessage());
        }finally{socket=null;publish();}
    }
    private synchronized void recordEvent(String event){
        lastEvent=event;
        String time=new SimpleDateFormat("HH:mm:ss",Locale.getDefault()).format(new Date());
        String line=time+" • "+event;
        SharedPreferences p=getSharedPreferences(PREFS,MODE_PRIVATE);
        String old=p.getString(PREF_EVENTS,"");
        String next=old+line+"\n";
        if(next.length()>18000)next=next.substring(next.length()-17000);
        p.edit().putString(PREF_EVENTS,next).apply();
        publish();
    }
    private void publish(){
        PacketCore c=core;
        String info=c==null?"Chưa có dữ liệu":("Gói: "+c.packets+"   TCP: "+c.tcpPackets+"   Khung: "+c.frames+"\nGửi: "+c.upFrames+"   Nhận: "+c.downFrames+"   Ứng viên thả câu: "+c.castBurstCandidates);
        Intent i=new Intent(ACTION_UPDATE).setPackage(getPackageName());
        i.putExtra(EXTRA_LOG,lastEvent);i.putExtra(EXTRA_STATS,info);
        sendBroadcast(i);
        main.post(()->{
            if(overlay!=null)overlay.setText("gid LIVE • chỉ đọc\n"+info+"\nFishID: Chưa giải mã\n"+lastEvent);
        });
    }
    private void showOverlayIfAllowed(){
        if(Build.VERSION.SDK_INT<23 || !Settings.canDrawOverlays(this))return;
        try{
            window=(WindowManager)getSystemService(Context.WINDOW_SERVICE);
            overlay=new TextView(this);
            overlay.setTextColor(Color.WHITE);overlay.setTextSize(12);
            overlay.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
            overlay.setPadding(20,12,20,12);
            GradientDrawable bg=new GradientDrawable();bg.setColor(0xdd12202e);bg.setCornerRadius(14);overlay.setBackground(bg);
            overlay.setText("gid LIVE\nChờ dữ liệu mạng...\nFishID: Chưa giải mã");
            WindowManager.LayoutParams lp=new WindowManager.LayoutParams(
                    (int)(getResources().getDisplayMetrics().density*290),WindowManager.LayoutParams.WRAP_CONTENT,
                    Build.VERSION.SDK_INT>=26?WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY:WindowManager.LayoutParams.TYPE_PHONE,
                    WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE|WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE|
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,PixelFormat.TRANSLUCENT);
            lp.alpha=0.75f; // Android 12: allow touches through FLAG_NOT_TOUCHABLE overlay (<=0.8 obscuring opacity)
            lp.gravity=Gravity.TOP|Gravity.CENTER_HORIZONTAL;lp.y=(int)(getResources().getDisplayMetrics().density*52);
            window.addView(overlay,lp);
        }catch(Exception ex){ overlay=null;window=null;recordEvent("Không thể hiển thị bảng nổi: "+ex.getMessage()); }
    }
    private void shutdown(){
        running.set(false);
        DatagramSocket s=socket;if(s!=null)s.close();
        main.post(()->{
            if(window!=null && overlay!=null){try{window.removeView(overlay);}catch(Exception ignored){}overlay=null;}
        });
    }
    @Override public void onDestroy(){ shutdown();super.onDestroy(); }
    @Override public IBinder onBind(Intent intent){return null;}
}
