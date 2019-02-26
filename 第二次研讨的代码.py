import random
import gmpy2 as gmp

import crypto
import sys

sys.modules['Crypto'] = crypto

from crypto import Random
from crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


class PrpCrypt(object):

    def __init__(self, key):
        self.key = key.encode('utf-8')
        self.mode = AES.MODE_CBC

    # 加密函数，如果text不足16位就用空格补足为16位，
    # 如果大于16当时不是16的倍数，那就补足为16的倍数。
    def encrypt(self, text):
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            # \0 backspace
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            # text = text + ('\0' * add)
            text = text + ('\0' * add).encode('utf-8')
        self.ciphertext = cryptor.encrypt(text)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, b'0000000000000000')
        plain_text = cryptor.decrypt(a2b_hex(text))
        # return plain_text.rstrip('\0')
        return bytes.decode(plain_text).rstrip('\0')

    def __str__(self):
        return self.key[:32]


def random_hex(len):
    result = ""
    for i in range(len):
        result += hex(random.randint(0x00, 0xFF)).replace('0x', '')
    return gmp.mpz('0x' + result)


def random_hex_str(len):
    result = ""
    for i in range(len):
        result += hex(random.randint(0x00, 0xFF)).replace('0x', '')
    return result


MODULE_CHAIN = [
    {
        'p': gmp.next_prime(random_hex(64)),
        'g': 5
    }
]


class Console(object):
    def __init__(self):
        self.network_key = 'shaobao123'
        self.MAC = random_hex_str(6)
        self.private_key = gmp.next_prime(random_hex(128))
        self.SESSIONID = None
        self.content = 'MOVE TO (3,4),\nSPEED 3.4KM/h'

    def send(self, string):
        print(string)
        # TODO BY SOCKET


class Point(object):
    def __init__(self, name):
        self.point_name = name
        self.network_key = 'shaobao123'
        self.MAC = random_hex(6)
        self.private_key = gmp.next_prime(random_hex(128))
        self.SESSIONID = None

        self.content = 'hello console! I am point {}'.format(name)

    def send(self, string):
        print(string)
        # TODO BY SOCKET


if __name__ == '__main__':


    C = Console()

    A = Point('A')

    p, g = MODULE_CHAIN[0]['p'], MODULE_CHAIN[0]['g']

    print("假设 控制台要给 无人机 A 发出信号。发送方 C 接收方 A")
    print("C 发送  g^c mod p 给 A")

    C.send('''
SMAC : {SMAC}
TMAC : {TMAC}
FLAG : HD-KEY-CHECK
CONTENT :  
--PUB KEY BEGIN--\n{CONTENT}\n---PUB KEY END---\n
    '''.format(
        SMAC=C.MAC,
        TMAC=A.MAC,
        CONTENT=gmp.powmod(g, C.private_key, p)
    ))

    #  A 发送  g^a mod p 给 C")
    A.send('''
SMAC : {SMAC}
TMAC : {TMAC}
FLAG : HD-KEY-CHECK
CONTENT :  
--PUB KEY BEGIN--\n{CONTENT}\n---PUB KEY END---\n
    '''.format(
        SMAC=A.MAC,
        TMAC=C.MAC,
        CONTENT=gmp.powmod(g, A.private_key, p)
    ))
    print("C 发送  A^c mod p 给 A")
    C.send('''
SMAC : {SMAC}
TMAC : {TMAC}
FLAG : HD-KEY-CHECK
CONTENT :  
--SHARE MSG BEGIN--\n{CONTENT}\n---SHARE MSG END---\n
    '''.format(
        SMAC=C.MAC,
        TMAC=A.MAC,
        CONTENT=gmp.powmod(gmp.powmod(g, A.private_key, p), C.private_key, p)
    ))
    print("A 确认  A^c mod p == C^a mod p 。则接受 C 的消息")
    if \
            gmp.powmod(gmp.powmod(g, A.private_key, p), C.private_key, p) == gmp.powmod(gmp.powmod(g, C.private_key, p),
                                                                                        A.private_key, p):
        A.SESSIONID = PrpCrypt(key='safddsafsadfasffwfeuiwjfapoiwjef')
        C.SESSIONID = PrpCrypt(key='safddsafsadfasffwfeuiwjfapoiwjef')

        A.send('''
SMAC : {SMAC}
TMAC : {TMAC}
FLAG : HD-KEY-CHECK
SESSION : {SESSION}
CONTENT :  
HELLO-CONSOLE
    '''.format(
            SMAC=A.MAC,
            TMAC=C.MAC,
            SESSION=A.SESSIONID.__str__()
            # CONTENT=gmp.powmod(gmp.powmod(g, A.private_key, p), C.private_key, p)
        ))

        encryption = C.SESSIONID.encrypt(C.content)

        C.send('''
SMAC : {SMAC}
TMAC : {TMAC}
FLAG : AES-MSG-SEND
SESSION : {SESSION}
CONTENT :  
{CONTENT}
        '''.format(
            SMAC=C.MAC,
            TMAC=A.MAC,
            SESSION=C.SESSIONID.__str__(),
            CONTENT=encryption
        ))
        A.send('''
SMAC : {SMAC}
TMAC : {TMAC}
FLAG : AES-MSG-GET
SESSION : {SESSION}
CONTENT :  
{CONTENT}
        '''.format(
            SMAC=A.MAC,
            TMAC=None,
            SESSION=A.SESSIONID.__str__(),
            CONTENT=C.SESSIONID.decrypt(encryption)
        ))


