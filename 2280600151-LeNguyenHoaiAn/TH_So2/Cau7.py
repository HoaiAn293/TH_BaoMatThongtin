# Nhập các dòng từ người dùng
print("Nhập các dòng văn bản (Nhập 'done' để kết thúc):")
lines = []

while True:
    line = input()
    if line.lower() == 'done':
        break
    lines.append(line)

# Chuyển các dòng đã nhập sang khi chuyển thành chữ in hoa:
print("Các dòng đã nhập sau khi chuyển thành chữ in hoa:")
for line in lines:
    print(line.upper())