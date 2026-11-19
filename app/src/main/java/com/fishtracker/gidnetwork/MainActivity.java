package com.fishtracker.gidnetwork;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/** PCAPdroid controls and viewer; no network-manipulation permissions. */
public final class MainActivity extends Activity {
    private static final int REQUEST_START=201;
    private static final int REQUEST_STOP=202;
    private TextView status, events;
    private final BroadcastReceiver updates=new BroadcastReceiver(){
        @Override public void onReceive(Context context,Intent intent){
            String s=intent.getStringExtra(CaptureService.EXTRA_STATS);
            if(s!=null)status.setText("Đang nhận PCAPdroid\n"+s+"\nFishID: Chưa giải mã");
            refreshLog();
        }
    };
    @Override public void onCreate(Bundle bundle){super.onCreate(bundle);
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18),dp(18),dp(18),dp(12));root.setBackgroundColor(0xff0e1622);
        ScrollView sv=new ScrollView(this);sv.addView(root);setContentView(sv);
        TextView title=text("gid • NETWORK LIVE",23,Color.WHITE,true);root.addView(title);
        TextView sub=text("Quan sát kết nối game trên PCAPdroid • Không ROOT • Không thay đổi dữ liệu",13,0xffacbfcd,false);
        root.addView(sub);gap(root,12);
        status=text("Chưa bắt đầu\nFishID: Chưa giải mã",17,0xff60d6f9,true);root.addView(status);gap(root,12);
        button(root,"BẮT ĐẦU ĐỌC MẠNG",v->startCapture());
        button(root,"DỪNG ĐỌC MẠNG",v->stopCapture());
        button(root,"CHO PHÉP BẢNG NỔI",v->requestOverlay());
        button(root,"CHIA SẺ NHẬT KÝ SỰ KIỆN",v->shareLog());
        gap(root,14);
        root.addView(text("NHẬT KÝ THỜI GIAN THỰC",14,0xffd0dbe5,true));
        events=text("",12,0xffe3ecf3,false);events.setMovementMethod(new ScrollingMovementMethod());
        events.setPadding(dp(10),dp(10),dp(10),dp(10));events.setBackgroundColor(0xff182535);root.addView(events);
        gap(root,12);
        root.addView(text("Chưa có bộ giải mã FishID. Mẫu phản hồi chỉ là ứng viên, không phải kết quả xác nhận.",13,0xffffb465,false));
        refreshLog();
    }
    private void startCapture(){
        try{
            Intent service=new Intent(this,CaptureService.class);
            if(Build.VERSION.SDK_INT>=26)startForegroundService(service);else startService(service);
            Intent api=pcapIntent("start");
            api.putExtra("pcap_dump_mode","udp_exporter");
            api.putExtra("collector_host","127.0.0.1");
            api.putExtra("collector_port",PacketCore.LISTEN_PORT);
            api.putExtra("app_filter","com.vnlord.happy");
            api.putExtra("dump_extensions",false);
            api.putExtra("full_payload",true);
            startActivityForResult(api,REQUEST_START);
        }catch(Exception ex){
            Toast.makeText(this,"Không mở được PCAPdroid: "+ex.getMessage(),Toast.LENGTH_LONG).show();
            stopService(new Intent(this,CaptureService.class));
        }
    }
    private void stopCapture(){
        try{startActivityForResult(pcapIntent("stop"),REQUEST_STOP);}
        catch(Exception ex){Toast.makeText(this,"Không điều khiển được PCAPdroid: "+ex.getMessage(),Toast.LENGTH_LONG).show();}
        stopService(new Intent(this,CaptureService.class));
        status.setText("Đã dừng\nFishID: Chưa giải mã");
    }
    private Intent pcapIntent(String action){
        Intent i=new Intent(Intent.ACTION_VIEW);
        i.setClassName("com.emanuelef.remote_capture","com.emanuelef.remote_capture.activities.CaptureCtrl");
        i.putExtra("action",action);
        return i;
    }
    @Override protected void onActivityResult(int request,int result,Intent data){
        super.onActivityResult(request,result,data);
        if(request==REQUEST_START && result!=RESULT_OK){
            status.setText("PCAPdroid chưa cho phép bắt gói tin.");
            stopService(new Intent(this,CaptureService.class));
        }else if(request==REQUEST_START){
            status.setText("Đã kích hoạt PCAPdroid. Mở game và bắt đầu câu.\nFishID: Chưa giải mã");
        }
    }
    private void requestOverlay(){
        if(Build.VERSION.SDK_INT<23||Settings.canDrawOverlays(this)){
            Toast.makeText(this,"Đã có quyền bảng nổi. Nếu đang chạy hãy dừng và bắt đầu lại gid.",Toast.LENGTH_LONG).show();return;
        }
        Intent i=new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,Uri.parse("package:"+getPackageName()));
        startActivity(i);
    }
    private void refreshLog(){
        if(events==null)return;
        String log=getSharedPreferences(CaptureService.PREFS,MODE_PRIVATE).getString(CaptureService.PREF_EVENTS,"");
        events.setText(log.isEmpty()?"Chưa có sự kiện. Nhấn BẮT ĐẦU ĐỌC MẠNG.":log);
    }
    private void shareLog(){
        String log=getSharedPreferences(CaptureService.PREFS,MODE_PRIVATE).getString(CaptureService.PREF_EVENTS,"");
        Intent send=new Intent(Intent.ACTION_SEND);send.setType("text/plain");
        send.putExtra(Intent.EXTRA_TEXT,"gid Network Live • nhật ký sự kiện (không chứa raw packet)\n"+log);
        startActivity(Intent.createChooser(send,"Chia sẻ nhật ký gid"));
    }
    @Override protected void onStart(){super.onStart();
        IntentFilter f=new IntentFilter(CaptureService.ACTION_UPDATE);
        if(Build.VERSION.SDK_INT>=33)registerReceiver(updates,f,Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(updates,f);
        refreshLog();
    }
    @Override protected void onStop(){try{unregisterReceiver(updates);}catch(Exception ignored){}super.onStop();}
    private TextView text(String s,int size,int color,boolean bold){TextView v=new TextView(this);v.setText(s);v.setTextSize(size);v.setTextColor(color);if(bold)v.setTypeface(Typeface.DEFAULT,Typeface.BOLD);return v;}
    private void button(LinearLayout l,String name,View.OnClickListener cb){Button b=new Button(this);b.setText(name);b.setAllCaps(false);b.setOnClickListener(cb);l.addView(b);}
    private void gap(LinearLayout l,int h){View v=new View(this);l.addView(v,new LinearLayout.LayoutParams(1,dp(h)));}
    private int dp(int n){return (int)(n*getResources().getDisplayMetrics().density+.5f);}
}
