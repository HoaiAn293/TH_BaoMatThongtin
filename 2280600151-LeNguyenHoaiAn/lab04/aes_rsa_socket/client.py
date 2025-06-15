import socket
import threading
import tkinter as tk
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

client_socket = None
client_key = None
server_public_key = None
aes_key = None

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode()

def send_message(event=None):
    message = message_entry.get()
    if message.strip() and aes_key and client_socket:
        encrypted_message = encrypt_message(aes_key, message)
        client_socket.send(encrypted_message)
        chat_display.config(state='normal')
        chat_display.insert(tk.END, f"Me: {message}\n")
        chat_display.config(state='disabled')
        chat_display.see(tk.END)
        message_entry.delete(0, tk.END)
        if message.strip().lower() == "exit":
            client_socket.close()
            root.quit()

def receive_message():
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                def notify_disconnect():
                    chat_display.config(state='normal')
                    chat_display.insert(tk.END, "⚠ Server closed connection.\n")
                    chat_display.config(state='disabled')
                    chat_display.see(tk.END)
                    status_label.config(text="Status: Disconnected", fg="red")
                root.after(0, notify_disconnect)
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            def update_chat():
                chat_display.config(state='normal')
                chat_display.insert(tk.END, f"Peer: {decrypted_message}\n")
                chat_display.config(state='disabled')
                chat_display.see(tk.END)
            root.after(0, update_chat)
        except:
            break

def enable_input_widgets():
    message_entry.config(state='normal')
    send_button.config(state='normal')

def socket_connect():
    global client_socket, client_key, server_public_key, aes_key
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 12345))
        client_key = RSA.generate(2048)
        server_public_key = RSA.import_key(client_socket.recv(2048))
        client_socket.send(client_key.publickey().export_key(format='PEM'))
        encrypted_aes_key = client_socket.recv(2048)
        cipher_rsa = PKCS1_OAEP.new(client_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        root.after(0, lambda: status_label.config(text="Status: Connected", fg="green"))
        root.after(0, enable_input_widgets)
        receive_thread = threading.Thread(target=receive_message, daemon=True)
        receive_thread.start()
    except Exception as e:
        root.after(0, lambda: status_label.config(text=f"Status: Error: {e}", fg="red"))
        root.after(0, lambda: chat_display.config(state='normal'))
        root.after(0, lambda: chat_display.insert(tk.END, f"Kết nối thất bại: {e}\n"))
        root.after(0, lambda: chat_display.config(state='disabled'))

root = tk.Tk()
root.title("Simple Secure Chat Client")
root.geometry("500x400")
root.resizable(False, False)

chat_frame = tk.Frame(root)
chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

chat_display = tk.Text(chat_frame, width=60, height=18, state='disabled', wrap=tk.WORD, bg="#f7f7f7")
chat_display.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(chat_frame, command=chat_display.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
chat_display['yscrollcommand'] = scrollbar.set

entry_frame = tk.Frame(root)
entry_frame.pack(padx=10, pady=5, fill=tk.X)

message_entry = tk.Entry(entry_frame, width=45, font=("Segoe UI", 10))
message_entry.pack(side=tk.LEFT, padx=(0,5), fill=tk.X, expand=True)
message_entry.bind("<Return>", send_message)
message_entry.config(state='disabled')

send_button = tk.Button(entry_frame, text="Send", width=8, command=send_message)
send_button.pack(side=tk.LEFT)
send_button.config(state='disabled')

status_label = tk.Label(root, text="Status: Connecting...", fg="orange", anchor='w')
status_label.pack(fill=tk.X, padx=10, pady=(0,5))

connect_thread = threading.Thread(target=socket_connect, daemon=True)
connect_thread.start()

root.mainloop()