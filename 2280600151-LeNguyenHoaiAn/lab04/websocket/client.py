import asyncio
import tkinter as tk
from tkinter import ttk
import tornado.websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import sys

# Khắc phục lỗi event loop trên Windows
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class WebSocketClientUI:
    def __init__(self, root, loop):
        self.root = root
        self.loop = loop
        self.connection = None

        self.root.title("💬 Secure Chat Client")
        self.root.geometry("600x450")
        self.root.configure(bg="#f0f0f0")
        self.root.resizable(False, False)

        self.chat_display = tk.Text(root, width=70, height=20, state='disabled', wrap=tk.WORD,
                                    bg="#ffffff", fg="#333333")
        self.chat_display.pack(pady=(10, 0), padx=10)

        message_frame = tk.Frame(root, bg="#f0f0f0")
        message_frame.pack(pady=10)

        self.message_entry = ttk.Entry(message_frame, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = ttk.Button(message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT)

        self.status_label = ttk.Label(root, text=" Status: Disconnected", foreground="red", background="#f0f0f0")
        self.status_label.pack(pady=(0, 10))

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.loop.create_task(self.start_connection())

    async def start_connection(self):
        self.status_label.config(text=" Status: Connecting...", foreground="orange")
        try:
            self.connection = await tornado.websocket.websocket_connect("ws://localhost:8888/websocket/")
            self.status_label.config(text="✅ Connected to server", foreground="green")
            self._append_message("✅ Connected to server.\n")
            self.loop.create_task(self.read_messages_loop())
        except Exception as e:
            self.status_label.config(text=" Connection Failed", foreground="red")
            self._append_message(f" Connection failed: {e}\n")

    async def read_messages_loop(self):
        while True:
            try:
                message = await self.connection.read_message()
                if message is None:
                    raise ConnectionError("Disconnected")
                self.on_message(message)
            except Exception as e:
                self._append_message(f"Error reading message: {e}\n")
                self.status_label.config(text=" Disconnected", foreground="red")
                await asyncio.sleep(3)
                await self.start_connection()
                break

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if not message:
            return

        try:
            if self.connection:
                self.connection.write_message(message)
                self._append_message(f" You: {message}\n")
                self.message_entry.delete(0, tk.END)
        except Exception as e:
            self._append_message(f" Send failed: {e}\n")
            self.status_label.config(text=" Disconnected", foreground="red")

    def on_message(self, message):
        self._append_message(f" Encrypted: {message}\n")
        try:
            decrypted = self.decrypt_message(message)
            self._append_message(f" Decrypted: {decrypted}\n")
        except Exception as e:
            self._append_message(f" Decryption failed: {e}\n")

    def decrypt_message(self, encrypted_base64):
        key = b"thisisaverysecret"      # 16 bytes key
        iv = b"thisis16bytesiv"         # 16 bytes IV
        encrypted_data = base64.b64decode(encrypted_base64)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data.decode()

    def _append_message(self, message):
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, message)
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')

    def on_closing(self):
        self.loop.stop()
        self.root.destroy()


async def update_tk(root):
    while True:
        root.update()
        await asyncio.sleep(0.01)


def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    root = tk.Tk()
    client_ui = WebSocketClientUI(root, loop)
    loop.create_task(update_tk(root))
    loop.run_forever()


if __name__ == "__main__":
    main()
