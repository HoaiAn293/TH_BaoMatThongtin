from QuanLySinhVien import QuanLySinhVien

qlsv = QuanLySinhVien()

while True:
    print("\n====== MENU ======")
    print("1. Nhập sinh viên")
    print("2. Cập nhật sinh viên")
    print("3. Xóa sinh viên")
    print("4. Tìm kiếm sinh viên theo tên")
    print("5. Sắp xếp theo điểm trung bình (GPA)")
    print("6. Sắp xếp theo tên")
    print("7. Hiển thị danh sách sinh viên")
    print("0. Thoát")
    
    try:
        key = int(input("Nhập lựa chọn của bạn: "))
    except ValueError:
        print("Vui lòng nhập một số!")
        continue

    if key == 1:
        print("Nhập sinh viên")
        qlsv.nhapSinhVien()
        print("Nhập sinh viên thành công")

    elif key == 2:
        if qlsv.soLuongSinhVien() > 0:
            print("Nhập ID sinh viên cần cập nhật:")
            ID = int(input())
            qlsv.updateSinhVien(ID)
        else:
            print("Danh sách sinh viên trống!")

    elif key == 3:
        if qlsv.soLuongSinhVien() > 0:
            print("Nhập ID sinh viên cần xóa:")
            ID = int(input())
            qlsv.deleteByID(ID)
        else:
            print("Danh sách sinh viên trống!")

    elif key == 4:
        if qlsv.soLuongSinhVien() > 0:
            print("Nhập tên sinh viên cần tìm:")
            name = input()
            result = qlsv.findByName(name)
            qlsv.showSinhVien(result)
        else:
            print("Danh sách sinh viên trống!")

    elif key == 5:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.sortByDiemTB()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("Danh sách sinh viên trống!")

    elif key == 6:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.sortByName()
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("Danh sách sinh viên trống!")

    elif key == 7:
        if qlsv.soLuongSinhVien() > 0:
            qlsv.showSinhVien(qlsv.getListSinhVien())
        else:
            print("Danh sách sinh viên trống!")

    elif key == 0:
        print("Bạn đã chọn thoát chương trình!")
        break

    else:
        print("Không có chức năng này! Hãy chọn lại.")
