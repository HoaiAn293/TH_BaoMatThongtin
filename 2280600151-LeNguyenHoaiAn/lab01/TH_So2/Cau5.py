so_gio_lam = float(input("Nhập số giờ làm mỗi tuần: "))
luong_gio = float(input("Nhập thu lao trên mỗi giờ theo tiêu chuẩn: "))

gio_tieu_chuan = 44  
gio_vuot_chuan = max(0, so_gio_lam - gio_tieu_chuan) 

thuc_linh = gio_tieu_chuan * luong_gio + gio_vuot_chuan * luong_gio * 1.5
print("Số tiền thực lĩnh của nhân viên:", thuc_linh)