# Mapping mã lệnh FishCast/Reel từ ARM64 (APK Tiểu Tuyết Lĩnh Chủ 1.64)

Nguồn: bản sao `libil2cpp.so` trong `split_config.arm64_v8a.apk` người dùng gửi. Đây là **offset RVA trong ELF**, không phải địa chỉ runtime. Không sử dụng can thiệp động, không kết nối game.

## Thả câu (cast)

Hàm: `X5Game.HomeFishNetMgr.HomeFishCastReq` tại RVA `0x0257945C`.

- RVA `0x025794CC`: `mov w0, #0x167F` (5759) trước khi gọi `0x02578AB0` (tạo gói) tại RVA `0x025794D0`.
- Hàm tạo gói `0x02578AB0` ghi `strh w19, [x21,#0x12]` tại RVA `0x02578B28` (lưu mã lệnh 16-bit vào header managed).
- RVA `0x02579548`: `mov w2, #0x1680` (5760); RVA `0x0257955C`: gửi qua `0x0255BD30` (GameClient.SendCSMsg), có callback `OnHomeFishCastRes`.

**Suy luận mạnh từ cấu trúc gọi:** request CMD=5759, expected response CMD=5760. Chưa xác minh số này trong plaintext mạng thực tế.

## Thu dây (reel)

Hàm: `X5Game.HomeFishNetMgr.HomeFishReelReq` tại RVA `0x025797B8`.

- RVA `0x0257982C`: `mov w0, #0x1681` (5761) trước gọi `0x02578AB0`.
- RVA `0x025798AC`: `mov w2, #0x1682` (5762) trước gọi `0x0255BD30`.

**Suy luận mạnh:** request CMD=5761, expected response CMD=5762. Đây là một phép kiểm tra chéo vì cặp lệnh liền nhau theo cùng mô hình gọi.

## FishID trong phản hồi

- `net.CSHomeFishCastRes` có hai trường metadata `FishID`, `Result`.
- Hàm `unpack` RVA `0x02BB39A8`: tại `0x02BB39BC` nạp địa chỉ trường `this +0x10` và gọi hàm đọc; kế đó xử lý đối tượng ở `this +0x18`. Đây là bằng chứng FishID được đọc đầu tiên trong cấu trúc đối tượng phản hồi. Không đủ để xác định offset byte trên dây nếu chưa giải mã và kiểm tra header/CRC.

## Nguồn khóa mã hóa

- `DodGame.NetClient.SetEncryptKey` RVA `0x02B35814` nhận đầu vào `x1`, gọi một phương thức encoding để tạo mảng byte, tiếp theo gọi `FastXXTEA.ToUInt32Array` RVA `0x01F8B1E0` với `w1=0`.
- `NetClient.GetEncodeKey` có đường dự phòng từ cấu hình kết nối nếu `m_encKey` chưa được đặt.
- **Chưa tìm được giá trị khóa thực tế.** Không được diễn dịch việc xác định hàm chuyển đổi thành đã phá được mã hóa.

## Hạn chế

Các mã này cần được xác nhận bằng bản tin đã giải mã đúng `FastXXTEA.DexxV2` và checksum nội bộ. Không công bố FishID từ ciphertext. Bản PCAP thô và thông tin phiên/khóa không có trong gói nghiên cứu.
