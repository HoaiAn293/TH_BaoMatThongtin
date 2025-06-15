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
        messagebox.showerror("Error", f"Failed to load server public key: {e}")
        return None

def calculate_shared_secret():
    file_path = filedialog.askopenfilename(title="Select Server Public Key", filetypes=[("PEM files", "*.pem")])
    if not file_path:
        return

    server_public_key = load_server_public_key(file_path)
    if not server_public_key:
        return

    parameters = server_public_key.parameters()
    private_key, public_key = generate_client_key_pair(parameters)
    shared_secret = derive_shared_secret(private_key, server_public_key)

    shared_secret_label.config(text=f"Shared Secret:\n{shared_secret.hex()}")

root = tk.Tk()
root.title("DH Key Exchange Client")
root.geometry("600x400")
root.resizable(False, False)

title_label = tk.Label(root, text="DH Key Exchange Client", font=("Segoe UI", 16, "bold"), fg="#333")
title_label.pack(pady=20)

load_key_button = tk.Button(root, text="Load Server Public Key", command=calculate_shared_secret, font=("Segoe UI", 12), bg="#4CAF50", fg="white", relief=tk.RAISED, bd=2)
load_key_button.pack(pady=20)

shared_secret_frame = tk.Frame(root, bg="#f7f7f7", relief=tk.SUNKEN, bd=2)
shared_secret_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

shared_secret_label = tk.Label(shared_secret_frame, text="Shared Secret: None", font=("Segoe UI", 12), wraplength=550, justify="left", bg="#f7f7f7", fg="#333")
shared_secret_label.pack(padx=10, pady=10)

root.mainloop()