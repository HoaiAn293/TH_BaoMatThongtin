from cipher.caesar.alphabet import ALPHABET

class CaesarCipher:
    def __init__(self):
        self.alphabet = ALPHABET

    def encrypt_text(self, text: str, key: int) -> str:
        alphabet_len = len(self.alphabet)
        text = text.upper()
        encrypted_text = []
        for letter in text:
            if letter in self.alphabet:
                index = self.alphabet.index(letter)
                output = self.alphabet[(index + key) % alphabet_len]
                encrypted_text.append(output)
            else:
                encrypted_text.append(letter) 
        return "".join(encrypted_text)

    def decrypt_text(self, text: str, key: int) -> str:
        alphabet_len = len(self.alphabet)
        text = text.upper()
        decrypted_text = []
        for letter in text:
            if letter in self.alphabet:
                index = self.alphabet.index(letter)
                output = self.alphabet[(index - key) % alphabet_len]
                decrypted_text.append(output)
            else:
                decrypted_text.append(letter)
        return "".join(decrypted_text)
