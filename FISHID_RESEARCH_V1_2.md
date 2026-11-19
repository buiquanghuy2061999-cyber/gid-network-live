# gid Network Live V1.2 — Đối chiếu 5 bản PCAP, chưa giải mã FishID

**Các dữ liệu được dùng:** 4 bản PCAP ngày 19/11 buổi sáng, 1 bản PCAP 16:30; APK 1.64 đã tải lên; 429 bản ghi FishID.

## Phát hiện có thể lặp lại

Một gói game **gửi đi 38 byte**, sau **50–450 ms** xuất hiện ít nhất **20 phản hồi 70 byte** ở phía nhận. Với năm bản ghi được cung cấp, phát hiện đúng **6 cụm ứng viên thả câu** và **0 cụm ở bản ghi không câu** (chưa phải kết quả kiểm định trên dữ liệu lớn).

- 11:05 có câu: 1 ứng viên, ~8,13–8,47 s.
- 11:11 không câu: 0 ứng viên.
- 11:13 có câu: 1 ứng viên, ~13,73–14,06 s.
- 11:22 thả nhưng không bắt được: 1 ứng viên, ~12,96–13,28 s.
- 16:30 ghi nhận theo thứ tự **Cá mỏ nhọn → Chép vây xanh → Cá củ cải**: 3 ứng viên, ~24,94–25,25 s, ~33,99–34,39 s, ~43,87–44,27 s.

Lưu ý: bản 11:05 người dùng từng ghi nhớ khoảng 3–4 con cá nhưng bộ dò chỉ tìm được 1 cụm lớn. Do đó **không thể suy ra độ nhạy 100% hay mỗi cá tương ứng một cụm**.

Sự kiện **11:22 có thả nhưng không bắt** cũng được phát hiện. Vì thế tuyệt đối **không** gọi bộ dò này là xác nhận bắt được cá. Đây là ứng viên **thả câu/cá xuất hiện** chưa chứng minh quan hệ opcode.

## Dữ liệu mã hóa

- 5 bản có **1.132 khung**; 4 bản đầu 513 khung, bản cuối 619 khung.
- Bản cuối có **618 khung 2E** và **1 khung 2F**. Nhánh 2E đi qua `FastXXTEA.DexxV2`, 2F qua XOR riêng.
- Trong bản ghi 16:30, khung game đầu tiên vào khoảng 10,16 giây kể từ lúc bắt PCAP; khung 2F tại ~12,16 giây. Giai đoạn đăng nhập có được ghi lại, nhưng điều đó **không** làm lộ khóa XXTEA trong văn bản rõ.
- `DodGame.NetClient.SetEncryptKey` gọi `FastXXTEA.ToUInt32Array` sau một lời gọi chuyển đổi chuỗi qua đối tượng encoding. Bộ mã hóa khóa đầu vào có thể không giới hạn ở tệp khóa đúng 16 byte; giả định 16 byte của công cụ V4 **cần xác minh lại** với mã game thực tế.
- **0 FishID thực sự được giải ra từ các gói 2E**. Các tên cá không có sẵn ở dạng tên tiếng Việt trong bảng 429 ID (bảng chứa `NameID`, không chứa bản địa hóa).

## V1.2 thay đổi gì

- Bổ sung `castBurstCandidates` và sự kiện "Ứng viên thả câu" khi phát hiện chuỗi 38B gửi + 20 khung 70B nhận trong 50–450 ms.
- Giữ cách gọi cũ cho nhóm 32 khung 70B khi đi kèm 150/278/1094 để không phá kiểm thử V1.1.
- Bổ sung kiểm thử trên 5 PCAP thật và kiểm thử tổng hợp có/không có gói yêu cầu.
- **Không** thêm đoán tên hoặc mã FishID, không sửa dữ liệu game.

## Điều cần có để giải FishID thật

(1) Xác định nguồn khóa `m_encKey` trong phiên đăng nhập, (2) kiểm chứng XXTEA với cặp plaintext/ciphertext đã biết, (3) hoàn thiện CRC và ánh xạ opcode sang `CSHomeFishCastRes`, (4) kiểm nghiệm ít nhất ba lượt câu có tên đối chiếu chính xác.

**Giới hạn:** Chưa biên dịch APK Android, chưa xác minh nhận UDP trực tiếp trên Black Shark 5. Chỉ phần lõi Java đã kiểm thử ngoại tuyến. Bản PCAP người dùng không được đưa vào ZIP/GitHub để bảo vệ dữ liệu phiên.

## Thời gian trễ phản hồi đã đo (từ PCAP, không phải độ trễ ứng dụng)

- 11:05: 103 ms, 33×70B.
- 11:13: 159 ms, 33×70B.
- 11:22: 176 ms, 30×70B.
- 16:30: 189 / 188 / 189 ms, ba cụm 32×70B.

Tên cá theo thứ tự quan sát chỉ được gắn nhãn *giả thuyết* cho ba cụm cuối.

**Kiểm soát sai lệch:** các điều kiện 38B+20×70B, 50–450 ms đã được chọn dựa trên chính năm bản PCAP này. Không có kiểm thử độc lập ngoài mẫu; tỷ lệ nhận dạng thực tế chưa đo được. Cơ chế không nhất thiết nhận diện được tất cả lượt câu; không nhận diện kết quả hay FishID.

## Mã lệnh game được truy từ mã máy

- `HomeFishCastReq` tạo request CMD **5759 (`0x167F`)**, phản hồi callback dùng CMD **5760 (`0x1680`)**.
- `HomeFishReelReq` tạo request CMD **5761 (`0x1681`)**, phản hồi callback dùng CMD **5762 (`0x1682`)**.
- Hàm tạo gói ghi số lệnh 16 bit vào trường header managed. Phân tích `CSHomeFishCastRes.unpack` thấy trường `FishID` là trường đầu tiên được đọc trong cấu trúc.
- Đây là **cặp opcode ứng viên độ tin cậy cao theo mã tĩnh**, vẫn **chưa đối chiếu trên plaintext mạng**. Chi tiết và địa chỉ RVA ở `evidence/PROTO_CMD_TRACE.md`.
