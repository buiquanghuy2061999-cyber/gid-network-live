# gid Network Live V1 — APK Android, chỉ đọc

Ứng dụng nguyên mẫu cho Black Shark 5 (Android 12 / MIUI 13), **không ROOT**.

## Giải pháp khả thi

**PCAPdroid** cung cấp VPN cục bộ để nhận gói từ game. **gid** gọi API chính thức của PCAPdroid và lắng nghe bản sao PCAP qua UDP `127.0.0.1:5123` trên chính điện thoại, rồi tự ghép TCP để phân tích các khung `32 45`.

Không tạo VPN thứ hai, không gửi request tới server game, không sửa APK/bộ nhớ, không đặt proxy hoặc cài chứng chỉ TLS.

Bộ lọc ứng dụng: `com.vnlord.happy`, kết nối game đã quan sát: TCP cổng `3341` (không cố định IP để tránh bị phụ thuộc máy chủ). Mỗi bản ghi nhận từ PCAPdroid có header PCAP 16 byte, tiếp đến IP (linktype 101), hoặc Ethernet (linktype 1).

## Tính năng đã viết

- Nút bắt đầu/dừng PCAPdroid bằng **CaptureCtrl Intent API** (có hộp thoại xin phép riêng của PCAPdroid).
- Foreground Service nhận UDP khi gid chạy nền, lọc TCP cổng 3341; tái lắp các segment và chống đếm trùng retransmission.
- Đếm gói TCP và khung 2E; nhận diện ứng viên yêu cầu 38 B ngoài chu kỳ 5 giây.
- Gắn nhãn ứng viên mẫu phản hồi 38 → 54 → 38 và 390 / 198 / 1142. Các mẫu này **không xác nhận** FishID hay kết quả câu.
- Hiển thị dashboard, nhật ký sự kiện tự lưu và chia sẻ log chỉ gồm thời điểm, số liệu; **không chứa payload mạng**.
- Bảng nổi (overlay) nhỏ trên game, `FLAG_NOT_TOUCHABLE` để không chặn thao tác; có thể tắt quyền. Ứng dụng yêu cầu quyền cửa sổ nổi riêng trên Android/MIUI.

## Trạng thái quan trọng

**FishID: CHƯA GIẢI MÃ.** Dữ liệu PCAP cũ chứa payload dài bội số 16 byte, có khả năng được mã hóa. APK này chỉ phát hiện ứng viên sự kiện trên luồng ciphertext. **Không suy đoán FishID từ kích thước khung hoặc byte ngẫu nhiên**.

## Cài trên Black Shark 5

1. Cài **PCAPdroid** chính thức từ Google Play/F-Droid (đã sử dụng trong dự án trước đây).
2. Đưa toàn bộ tệp trong thư mục ZIP (đừng đưa nguyên ZIP) lên **root repository GitHub MỚI** (đề nghị `gid-network-live` để tránh xung đột với Fish-V1 đang dùng). Nếu dùng repo cũ, xóa những file Java/workflow cũ không còn liên quan; không gộp hai project.
3. Vào GitHub → Actions → `Build gid Network Live APK` → Run workflow. Mở lần chạy đã hoàn thành → Artifacts → `gid-network-live-debug-apk`.
4. Cài `app-debug.apk` trên máy. Package riêng `com.fishtracker.gidnetwork` nên không cần gỡ gid ảnh cũ.
5. Mở gid Network → **Cho phép bảng nổi** (nếu muốn hiển thị trên game), quay lại gid, nhấn **Bắt đầu đọc mạng**. Chấp nhận yêu cầu VPN/PCAPdroid.
6. Mở game. Dữ liệu/ứng viên hiện lên bảng nổi và nhật ký.
7. Nếu máy MIUI đóng gid khi chuyển sang game, vào quản lý pin cho gid và cho phép hoạt động nền. Trạng thái vẫn sẽ phụ thuộc chính sách tiết kiệm pin trên máy.
8. Nhấn **Dừng đọc mạng** khi không dùng.

## Kiểm thử hiện có

Đã chạy thử phần `PacketCore.java` thuần Java với **4 PCAP của người dùng**:

- 11:05 — 138 khung
- 11:11 — 97 khung
- 11:13 — 144 khung
- 11:22 — 134 khung
- **Tổng 513 khung**, đúng phân tích trước. Mẫu 38→54→38 ở 11:05, 11:13, 11:22; mẫu 390/198/1142 ở 11:05, 11:13.

Chưa có môi trường Android SDK để biên dịch APK trực tiếp trong phiên này; mã Android và tích hợp PCAPdroid **chưa thử trên Black Shark 5**. Nếu workflow đỏ, chụp bước lỗi để sửa đúng phần.

Chạy kiểm thử Java trên máy có JDK 17:

```bash
mkdir -p build-test
javac -encoding UTF-8 -d build-test app/src/main/java/com/fishtracker/gidnetwork/PacketCore.java tests/SyntheticProtocolTest.java tests/PacketCorePcapTest.java
java -cp build-test SyntheticProtocolTest
java -cp build-test PacketCorePcapTest /path/to/PCAPdroid_*.pcap
```

## Cấu trúc

- `app/src/main/java/com/fishtracker/gidnetwork/PacketCore.java`: xử lý PCAP/TCP/khung và ứng viên sự kiện, thuần Java.
- `CaptureService.java`: nhận UDP, lưu nhật ký, thông báo, overlay.
- `MainActivity.java`: giao diện và gọi API PCAPdroid.
- `.github/workflows/build-apk.yml`: pipeline biên dịch APK debug bằng GitHub Actions.

## Nguồn và giới hạn

PCAPdroid developer API: https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md

Mẫu code gốc PCAPReceiver: https://github.com/emanuele-f/PCAPReceiver

Chỉ hỗ trợ cổ điển PCAP, IPv4, TCP cổng 3341. Không đọc FishID plaintext, không giải mã cipher, không phân tích IPv6. Khi PCAPdroid chưa được cấp phép hoặc đang được VPN khác sử dụng, có thể không bắt được gói. Cần PCAPdroid phiên bản hỗ trợ UDP Exporter API.

## Quyền riêng tư

Dữ liệu PCAP thô không được lưu và không được tải đi. Nhật ký lưu trong bộ nhớ riêng ứng dụng chỉ có metadata sự kiện; người dùng có thể chủ động chia sẻ nhật ký. UDP chỉ lắng nghe tại loopback 127.0.0.1. Không có mã gửi gói tin ra mạng.


## V1.1 — full-login PCAP support (2026-11-19)
- Thêm cổng TCP 3331, song song cổng 3341.
- Cho phép khung 2F với payload bội số 4; chỉ đếm khung, không phân tích chat hoặc thông tin tài khoản.
- Bổ sung kiểm thử bản ghi 619 khung (618 x 2E, 1 x 2F).
- Lưu ý: vẫn chưa có khóa XXTEA để giải mã FishID thật. Không gán FishID dựa vào kích cỡ gói.

## Chính sách sự kiện V1.1
- Không còn cảnh báo câu cá từ các mẫu độ dài đơn lẻ 38, 38→54→38 hoặc 390/198/1142 — dễ báo sai.
- Chỉ thông báo **cụm giao thức 32×70 + 150/278/1094** khi xuất hiện; không gán ID hoặc gọi đó là kết quả câu cá.
- Bảng nổi đặt độ trong suốt cửa sổ 0.75 để giảm nguy cơ chặn thao tác trên Android 12; chưa thử trên máy thực.


## V1.2 — liên hệ yêu cầu 38 byte với cụm phản hồi 70 byte

- Thêm bộ dò **ứng viên thả câu**, khi 1 khung gửi 38 byte được theo sau bởi ít nhất 20 khung nhận 70 byte trong khoảng 50–450 ms.
- Trên 5 PCAP của người dùng: 6 sự kiện ứng viên (11:05: 1, 11:11 đứng chờ: 0, 11:13: 1, 11:22 thả nhưng không bắt: 1, 16:30: 3).
- Không thể gọi đây là xác nhận bắt cá hoặc FishID. Ba tên cá mới chỉ có thứ tự quan sát; chưa giải được trường ID trong `2E`.
- Bảng nổi hiện bộ đếm *Ứng viên thả câu*; gỡ cảnh báo trùng cho mẫu cụm 32×70.
- Bản kiểm thử Java chạy đủ 1.132 khung và bài test tổng hợp gồm tín hiệu dương + âm.

Báo cáo nghiên cứu: `FISHID_RESEARCH_V1_2.md`. Chưa có APK Android được xác minh.


## Bằng chứng lệnh game (từ APK, không giải mã PCAP)

Tìm được hai cặp CMD từ hàm tạo và gửi yêu cầu: Cast 5759/5760; Reel 5761/5762. Xem `evidence/PROTO_CMD_TRACE.md`. Đây là ứng viên opcode cần xác nhận với bản rõ, **không** phải FishID.
