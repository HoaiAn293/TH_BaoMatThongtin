import tornado.ioloop
import tornado.websocket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64


class WebSocketServer(tornado.websocket.WebSocketHandler):
    def open(self):
        print(" Client connected.")

    def on_message(self, message):
        print(f" Received from client: {message}")
        try:
            encrypted = self.encrypt_message(message)

            self.write_message(encrypted)

            print(f" Sent encrypted: {encrypted}")
        except Exception as e:
            print(f" Error: {e}")
            # self.close()

    def on_close(self):
        print(" Client disconnected.")

    def check_origin(self, origin):
        return True

    def encrypt_message(self, message):
        key = b"thisisaverysecret"       
        iv = b"thisis16bytesiv"           
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(message.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(encrypted).decode()


def main():
    app = tornado.web.Application([
        (r"/websocket/", WebSocketServer),
    ])
    app.listen(8888)
    print("WebSocket server running at ws://localhost:8888/websocket/")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    main()
