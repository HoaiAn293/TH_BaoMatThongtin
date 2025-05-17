def xoa_phan_tu(dictionnary,key):
    if key in dictionnary:
        del dictionnary[key]
        return True
    else:
        return False
    
my_dict = {'a': 1, 'b': 2, 'c': 3,'d': 4}
key_to_delete = 'b'
result = xoa_phan_tu(my_dict, key_to_delete)
if result:
    print("Phần tu tử đã được từ Dictionary: ",my_dict)
else:
    print("Khong tim thay phan tu trong Dictionary")