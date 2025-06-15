import base64
import tkinter as tk
from tkinter import filedialog, messagebox

def encode_to_file(input_string, filename="data.txt"):
    encoded_bytes = base64.b64encode(input_string.encode("utf-8"))
    encoded_string = encoded_bytes.decode("utf-8")
    with open(filename, "w") as file:
        file.write(encoded_string)
    return filename

def decode_from_file(filename="data.txt"):
    try:
        with open(filename, "r") as file:
            encoded_string = file.read().strip()
        decoded_bytes = base64.b64decode(encoded_string)
        decoded_string = decoded_bytes.decode("utf-8")
        return decoded_string
    except Exception as e:
        return f"Lỗi: {e}"

def run_gui():
    def encode_action():
        input_string = entry_input.get()
        filename = entry_file.get() or "data.txt"
        if not input_string:
            messagebox.showwarning("Thiếu dữ liệu", "Vui lòng nhập thông tin cần mã hóa.")
            return
        encode_to_file(input_string, filename)
        messagebox.showinfo("Thành công", f"Đã mã hóa và ghi vào tệp {filename}")

    def decode_action():
        filename = entry_file.get() or "data.txt"
        result = decode_from_file(filename)
        entry_output.delete(0, tk.END)
        entry_output.insert(0, result)

    def browse_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_file.delete(0, tk.END)
            entry_file.insert(0, file_path)

    root = tk.Tk()
    root.title("Base64 Encode/Decode")
    root.geometry("400x220")

    tk.Label(root, text="Thông tin cần mã hóa:").pack()
    entry_input = tk.Entry(root, width=50)
    entry_input.pack(pady=2)

    tk.Label(root, text="Tên file (mặc định: data.txt):").pack()
    frame_file = tk.Frame(root)
    frame_file.pack(pady=2)
    entry_file = tk.Entry(frame_file, width=38)
    entry_file.pack(side=tk.LEFT)
    tk.Button(frame_file, text="Chọn file", command=browse_file).pack(side=tk.LEFT, padx=2)

    tk.Button(root, text="Mã hóa và lưu", command=encode_action).pack(pady=4)
    tk.Button(root, text="Giải mã từ file", command=decode_action).pack(pady=2)

    tk.Label(root, text="Kết quả giải mã:").pack()
    entry_output = tk.Entry(root, width=50)
    entry_output.pack(pady=2)

    root.mainloop()

if __name__ == "__main__":
    run_gui()
