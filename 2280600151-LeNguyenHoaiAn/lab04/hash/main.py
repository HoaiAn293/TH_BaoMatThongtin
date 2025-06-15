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
        messagebox.showwarning("Cảnh báo", "Vui lòng nhập chuỗi để mã hóa.")
        return

    selected_algorithm = algorithm_combobox.get()
    if selected_algorithm == "MD5":
        hash_result = calculate_md5(input_string)
    elif selected_algorithm == "SHA-256":
        hash_result = calculate_sha256(input_string)
    elif selected_algorithm == "SHA-3":
        hash_result = calculate_sha3(input_string)
    else:
        messagebox.showerror("Lỗi", "Vui lòng chọn thuật toán hợp lệ.")
        return

    result_text.config(state="normal")
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, hash_result)
    result_text.config(state="disabled")

# Giao diện
root = tk.Tk()
root.title("Hashing Algorithms")
root.geometry("700x450")
root.resizable(False, False)
root.configure(bg="white")

title_label = tk.Label(root, text="🔐 Hash Generator", font=("Segoe UI", 22, "bold"), bg="white", fg="#2c3e50")
title_label.pack(pady=15)

main_frame = tk.Frame(root, bg="white")
main_frame.pack(pady=10)

# Chọn thuật toán
algorithm_label = tk.Label(main_frame, text="Thuật toán băm:", font=("Segoe UI", 14), bg="white", anchor="w")
algorithm_label.grid(row=0, column=0, sticky="w", pady=5)

algorithm_combobox = ttk.Combobox(main_frame, values=["MD5", "SHA-256", "SHA-3"], font=("Segoe UI", 12), state="readonly", width=20)
algorithm_combobox.grid(row=0, column=1, padx=10, pady=5)
algorithm_combobox.set("MD5")

# Nhập chuỗi
input_label = tk.Label(main_frame, text="Nhập chuỗi cần mã hóa:", font=("Segoe UI", 14), bg="white", anchor="w")
input_label.grid(row=1, column=0, sticky="w", pady=10)

input_entry = tk.Entry(main_frame, font=("Segoe UI", 12), width=50, bg="#f9f9f9", relief="solid", bd=1)
input_entry.grid(row=1, column=1, padx=10, pady=10)

# Nút tính toán
calculate_button = tk.Button(root, text="Tạo mã băm", command=calculate_hash, font=("Segoe UI", 13), bg="#3498db", fg="white", padx=20, pady=5, relief="flat")
calculate_button.pack(pady=15)

# Kết quả
result_label = tk.Label(root, text="Kết quả mã hóa:", font=("Segoe UI", 14, "bold"), bg="white", fg="#2c3e50")
result_label.pack(pady=(10, 5))

result_text = tk.Text(root, height=4, width=80, font=("Consolas", 12), wrap="word", bg="#f0f0f0", bd=1, relief="solid")
result_text.pack()
result_text.config(state="disabled")

root.mainloop()
