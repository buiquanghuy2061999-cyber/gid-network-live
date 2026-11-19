# Đối chiếu PCAP đăng nhập + 3 cá — gid Network Live V1.1

- Bản mới: **619 khung** từ luồng TCP 118.26.111.64:3331; 29 khung gửi, 590 khung nhận.
- `2E`: 618; `2F`: 1. `2F` cần bộ xử lý XOR riêng, không đồng nhất với XXTEA.
- Người chơi ghi nhận thứ tự: (1) Cá mỏ nhọn; (2) Chép vây xanh; (3) Cá củ cải.
- Các cụm mạng tương tự: ~16:31:12, ~16:31:21, ~16:31:31 theo giờ VN. **Chưa xác nhận** cụm nào là lượt câu.
- Vẫn **0 FishID được giải mã trực tiếp**; chưa có khóa XXTEA đã xác minh.
- Bản cập nhật app chỉ hỗ trợ *nhận biết* thêm cổng/khung, không công bố số ID giả.
- PCAP đăng nhập có thể chứa thông tin cá nhân/phiên; không đưa bản PCAP lên GitHub công khai.
