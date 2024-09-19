# Mã hóa/Giải mã AES

Dự án này minh họa việc mã hóa và giải mã AES sử dụng thư viện C++ và ứng dụng C#. Thư viện C++ cung cấp các chức năng mã hóa và giải mã AES, trong khi ứng dụng C# tương tác với thư viện để thực hiện các thao tác mã hóa và giải mã.

## Cấu trúc dự án

- **AES/**: Chứa phần triển khai C++ của mã hóa và giải mã AES.
  - `AES.h`: Tệp tiêu đề cho lớp AES.
  - `AES.cpp`: Tệp triển khai cho lớp AES.
- **Testing/**: Chứa ứng dụng C# sử dụng thư viện AES.
  - `Program.cs`: Tệp chương trình chính minh họa việc sử dụng thư viện AES.

## Yêu cầu

- Visual Studio (để xây dựng các dự án C++ và C#)
- Trình biên dịch C++
- .NET SDK

## Xây dựng dự án

### Xây dựng thư viện AES

1. Mở dự án AES trong Visual Studio.
2. Xây dựng dự án để tạo tệp `AES.dll`.

### Xây dựng ứng dụng C#

1. Mở dự án Testing trong Visual Studio.
2. Đảm bảo rằng đường dẫn đến `AES.dll` trong `Program.cs` là chính xác:
    
3. Xây dựng dự án.

## Chạy ứng dụng

1. Chạy ứng dụng C# từ Visual Studio hoặc dòng lệnh.
2. Ứng dụng sẽ:
   - Tạo một khóa AES.
   - Mã hóa một văn bản mẫu.
   - Giải mã dữ liệu đã mã hóa.
   - Hiển thị kết quả.

## Ví dụ đầu ra

## Thư viện AES C++

### AES.h

Tệp `AES.h` chứa khai báo của lớp `AES` và các phương thức của nó cho mã hóa và giải mã AES.

### AES.cpp

Tệp `AES.cpp` chứa triển khai các phương thức của lớp `AES`.

## Ứng dụng C#

### Program.cs

Tệp `Program.cs` chứa chương trình chính minh họa việc sử dụng thư viện AES. Nó sử dụng P/Invoke để gọi các hàm từ `AES.dll`.

