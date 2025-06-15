import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
from Crypto.Hash import SHA3_256

def calculate_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()

def calculate_sha256(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

def calculate_sha3(input_string):
    sha3_hash = SHA3_256.new()
    sha3_hash.update(input_string.encode('utf-8'))
    return sha3_hash.hexdigest()

def calculate_hash():
    input_string = input_entry.get()
    if not input_string.strip():
        messagebox.showwarning("Warning", "Please enter a string to hash.")
        return

    selected_algorithm = algorithm_combobox.get()
    if selected_algorithm == "MD5":
        hash_result = calculate_md5(input_string)
    elif selected_algorithm == "SHA-256":
        hash_result = calculate_sha256(input_string)
    elif selected_algorithm == "SHA-3":
        hash_result = calculate_sha3(input_string)
    else:
        messagebox.showerror("Error", "Please select a valid hashing algorithm.")
        return

    result_label.config(text=f"Hash Result:\n{hash_result}")

# Tạo giao diện
root = tk.Tk()
root.title("Hashing Algorithms")
root.geometry("600x400")
root.resizable(False, False)
root.configure(bg="#f0f0f0")

# Tiêu đề
title_label = tk.Label(root, text="Hashing Algorithms", font=("Segoe UI", 20, "bold"), fg="#333", bg="#f0f0f0")
title_label.pack(pady=20)

# Chọn thuật toán băm
algorithm_label = tk.Label(root, text="Select Hashing Algorithm:", font=("Segoe UI", 14), bg="#f0f0f0", fg="#333")
algorithm_label.pack(pady=10)

algorithm_combobox = ttk.Combobox(root, values=["MD5", "SHA-256", "SHA-3"], font=("Segoe UI", 12), state="readonly")
algorithm_combobox.pack(pady=10)
algorithm_combobox.set("MD5")  # Mặc định chọn MD5

# Ô nhập chuỗi
input_label = tk.Label(root, text="Enter String to Hash:", font=("Segoe UI", 14), bg="#f0f0f0", fg="#333")
input_label.pack(pady=10)

input_entry = tk.Entry(root, width=50, font=("Segoe UI", 12))
input_entry.pack(pady=10)

# Nút tính toán
calculate_button = tk.Button(root, text="Generate Hash", command=calculate_hash, font=("Segoe UI", 12), bg="#4CAF50", fg="white", relief=tk.RAISED, bd=2)
calculate_button.pack(pady=10)

# Nhãn hiển thị kết quả
result_label = tk.Label(root, text="Hash Result: None", font=("Segoe UI", 12), fg="#333", wraplength=550, justify="left", bg="#f0f0f0")
result_label.pack(pady=10)

# Chạy giao diện
root.mainloop()