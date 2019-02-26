import sys
import Crypto
import base64
from Crypto.Cipher import AES


class AESCipher(object):

    def __init__(self, key):
        while len(key) % 16 != 0:
            key += '\0'
        self.key = str.encode(key)
        self.iv = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".encode('ascii','ignore')  # 16位字符，用来填充缺失内容，可固定值也可随机字符串，具体选择看需求。

    def __pad(self, text):
        """填充方式，加密内容必须为16字节的倍数，若不足则使用self.iv进行填充"""
        text_length = len(text)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        return text + pad * amount_to_pad

    def __unpad(self, text):
        if type(text[-1])==type(1):
            pad = text[-1]
            return text[:-pad]
        else:
            pad = ord(text[-1])
            return text[:-pad]

    def encrypt(self, raw):
        """加密"""
        raw = self.__pad(raw)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return base64.b64encode(cipher.encrypt(raw.encode('ascii','ignore')))

    def decrypt(self, enc):
        """解密"""
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        # print(cipher.decrypt(enc))
        return self.__unpad(cipher.decrypt(enc))

# if __name__ == '__main__':
#     e = AESCipher('8ymWLWJzYA1MvLF8')
#     secret_data = "6860795567181583<REQDATA></REQDATA>242BB99CE386F2B1EA19CCCF606D20E2"
#     enc_str = e.encrypt(secret_data)
#     print('enc_str: ' + enc_str.decode())
#     dec_str = e.decrypt(enc_str)
#     print('dec str: ' + dec_str)
