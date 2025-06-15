import socket
import threading
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

client_key = RSA.generate(2048)
server_public_key = RSA.import_key(client_socket.recv(2048))
client_socket.send(client_key.publickey().export_key(format='PEM'))
encrypted_aes_key = client_socket.recv(2048)
cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

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

def receive_message():
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:
                chat_display.insert(tk.END, "⚠ Server closed connection.\n")
                break
            decrypted_message = decrypt_message(aes_key, encrypted_message)
            chat_display.configure(state='normal')
            chat_display.insert(tk.END, f"Client1: {decrypted_message}\n")
            chat_display.configure(state='disabled')
            chat_display.see(tk.END)
        except:
            break

def send_message(event=None):
    message = message_entry.get()
    if message.strip():
        encrypted_message = encrypt_message(aes_key, message)
        client_socket.send(encrypted_message)
        chat_display.configure(state='normal')
        chat_display.insert(tk.END, f"Client2: {message}\n")
        chat_display.configure(state='disabled')
        chat_display.see(tk.END)
        message_entry.delete(0, tk.END)
        if message.strip().lower() == "exit":
            client_socket.close()
            root.quit()

root = tk.Tk()
root.title("Secure Chat Client")
root.geometry("600x500")
root.resizable(False, False)

style = ttk.Style()
style.theme_use("clam")

chat_display = ScrolledText(root, width=70, height=25, font=("Segoe UI", 10), wrap=tk.WORD)
chat_display.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
chat_display.configure(state='disabled', background="#f7f7f7", relief=tk.GROOVE)

message_entry = ttk.Entry(root, width=55, font=("Segoe UI", 10))
message_entry.grid(row=1, column=0, padx=10, pady=5, sticky="w")
message_entry.bind("<Return>", send_message)

send_button = ttk.Button(root, text="Send", command=send_message)
send_button.grid(row=1, column=1, padx=5, pady=5, sticky="e")

status_label = ttk.Label(root, text="Status: Connected", font=("Segoe UI", 10), foreground="green")
status_label.grid(row=2, column=0, columnspan=2, pady=5)

receive_thread = threading.Thread(target=receive_message, daemon=True)
receive_thread.start()

root.mainloop()