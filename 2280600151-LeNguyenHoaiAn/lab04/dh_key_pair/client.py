import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_client_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, server_public_key):
    shared_secret = private_key.exchange(server_public_key)
    return shared_secret

def load_server_public_key(file_path):
    try:
        with open(file_path, "rb") as f:
            server_public_key = serialization.load_pem_public_key(f.read())
        return server_public_key
    except Exception as e:
        messagebox.showerror("Lỗi", f"Tải public key thất bại: {e}")
        return None

def calculate_shared_secret():
    file_path = filedialog.askopenfilename(
        title="Chọn file Server Public Key",
        filetypes=[("PEM files", "*.pem")]
    )
    if not file_path:
        return

    server_public_key = load_server_public_key(file_path)
    if not server_public_key:
        return

    parameters = server_public_key.parameters()
    private_key, public_key = generate_client_key_pair(parameters)
    shared_secret = derive_shared_secret(private_key, server_public_key)

    shared_secret_text.config(state='normal')
    shared_secret_text.delete(1.0, tk.END)
    shared_secret_text.insert(tk.END, shared_secret.hex())
    shared_secret_text.tag_add('all', '1.0', tk.END)
    shared_secret_text.config(state='disabled')  # Không cho sửa nhưng vẫn copy được
    info_label.config(text="Đã sinh khóa bí mật chung thành công!")

def copy_shared_secret():
    root.clipboard_clear()
    root.clipboard_append(shared_secret_text.get('1.0', tk.END).strip())
    info_label.config(text="Đã copy shared secret vào clipboard!")

# Giao diện chính
root = tk.Tk()
root.title("Diffie-Hellman Key Exchange Client")
root.geometry("720x480")
root.resizable(False, False)
root.configure(bg="#f8fafd")

# Header
header = tk.Label(
    root, 
    text="Diffie-Hellman Key Exchange", 
    font=("Segoe UI", 20, "bold"), 
    fg="#1e3d59", 
    bg="#f8fafd"
)
header.pack(pady=(20, 10))

guide = tk.Label(
    root, 
    text="1. Chọn file public key của server (.pem)\n2. Hệ thống sẽ tạo shared secret tương ứng",
    font=("Segoe UI", 12), 
    fg="#555", 
    bg="#f8fafd",
    justify="center"
)
guide.pack()

# Button chọn key
choose_btn = tk.Button(
    root, 
    text="Chọn Server Public Key", 
    command=calculate_shared_secret,
    font=("Segoe UI", 13, "bold"), 
    bg="#28a745", 
    fg="white", 
    relief=tk.FLAT, 
    padx=16, pady=8
)
choose_btn.pack(pady=12)

# Copy button
copy_btn = tk.Button(
    root, 
    text="Copy Shared Secret", 
    command=copy_shared_secret,
    font=("Segoe UI", 11), 
    bg="#007bff", 
    fg="white", 
    relief=tk.FLAT, 
    padx=12, pady=6
)
copy_btn.pack()

# Thông tin trạng thái
info_label = tk.Label(root, text="", font=("Segoe UI", 11), fg="#007bff", bg="#f8fafd")
info_label.pack(pady=(5, 10))

# Frame chứa kết quả
frame = tk.Frame(root, bg="#eaf0f6", bd=2, relief=tk.GROOVE)
frame.pack(padx=24, pady=10, fill=tk.BOTH, expand=True)

result_title = tk.Label(
    frame, 
    text=" Shared Secret (hex):", 
    font=("Segoe UI", 13, "bold"), 
    bg="#eaf0f6", 
    fg="#1e3d59", 
    anchor="w"
)
result_title.pack(anchor='w', padx=12, pady=(12, 4))

shared_secret_text = tk.Text(
    frame, 
    height=6, 
    font=("Consolas", 12), 
    wrap=tk.WORD, 
    bg="#fefefe", 
    fg="#222", 
    bd=1, 
    relief=tk.SOLID
)
shared_secret_text.pack(padx=12, pady=8, fill=tk.BOTH, expand=True)
shared_secret_text.insert(tk.END, "Chưa có khóa bí mật chung.")
shared_secret_text.config(state='disabled')

root.mainloop()
