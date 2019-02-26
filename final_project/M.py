import random
import gmpy2 as gmp

import Crypto
import sys

sys.path.append('./config')

from collections import OrderedDict
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from config import DEVICE_ID_DICT, dict2file, file2dict, COMMUNICATION_KEY_DICT, IPADDR_DICT
from aesFunc import AESCipher


class MobileDevice(object):
    def __init__(self, NAME, DEVICE_ID, kp, IP):
        self.IP = IP
        self.IP_TARGET = None
        self.DEVICE_NAME = NAME
        self.KP = kp
        self.DEVICE_ID = DEVICE_ID
        self.COMMUNICATION_KEY = COMMUNICATION_KEY_DICT['K' + NAME]  # 之后会改成AES密钥
        self.MAIN_COMMUNICATION_KEY = None

    def first_send(self):
        data = OrderedDict()
        data['SIP'] = self.IP
        data['TIP'] = IPADDR_DICT['WALL']
        data['SMAC'] = self.DEVICE_ID  # SMAC
        data['TMAC'] = DEVICE_ID_DICT['MB']  # TMAC
        data['A_COMMUNICATION_KEY'] = self.COMMUNICATION_KEY  # KEY
        data['CONTENT'] = 'HELLO WALL I WANT TO FIND B'  # CONTENT
        data['FLAG'] = 'CER-1-SEND'
        print("向WALL发送与B通信请求，用公钥加密")
        print("Raw Data")
        print(data)
        dict2file(data, 'tmp.txt')
        # file2dict('tmp.txt')
        self._encode_data()
        print("Encode Data")
        print(open('tmp.txt', 'rb').read())

    def fourth_verify_and_send(self):
        print("用自己的通信密钥KB解密数据")
        self._decode_data(function_id=2, key=COMMUNICATION_KEY_DICT['KB'])
        dict = file2dict('tmp.txt')
        if True:
            pass
            print("Decode Data")
            print(dict)
            self.IP_TARGET = dict['IP_TARGET']
            print("经过一些验证措施之后，保存A的IP地址")
            # 省略一些验证步骤
        else:
            print('get false msg! ')

    def fifth_send(self):
        data = OrderedDict()
        data['SIP'] = self.IP
        data['TIP'] = IPADDR_DICT['WALL']
        data['SMAC'] = self.DEVICE_ID  # SMAC
        data['TMAC'] = DEVICE_ID_DICT['WALL']  # TMAC
        data['C_COMMUNICATION_KEY'] = gmp.mpz(__import__('random').randint(0xFFFFFF0000, 0xFFFFFFFFFF))
        self.MAIN_COMMUNICATION_KEY = data['C_COMMUNICATION_KEY']
        # COMMUNICATION_KEY_DICT['KC']  # should be randomized
        data['CONTENT'] = 'HERE IS MY KEY'  # CONTENT
        data['FLAG'] = 'CER-5-GEN_KC'
        print("生成随机的主通信密钥，用KB加密，并将主通信密钥保存在数据包中发给WALL")
        print("Raw Data")
        print(data)
        dict2file(data, 'tmp.txt')
        self._encode_data(2, key=self.COMMUNICATION_KEY)
        print("Encode Data")
        print(open('tmp.txt', 'rb').read())


    def seventh_get(self):
        print("A用KA解密数据，得到主通信密钥和B的IP地址，验证结束")
        self._decode_data(function_id=2, key=self.COMMUNICATION_KEY)
        dict = file2dict('tmp.txt')
        print("Decode Data")
        print(dict)
        self.IP_TARGET = dict['IP_TARGET']
        self.MAIN_COMMUNICATION_KEY = dict['KC']

    def commnication_send(self):
        print("发送的时候，发送方用主通信密钥加密数据")
        data = OrderedDict()
        # 看上去是这么发，实际上IP地址本来就包含在数据包中，这么做只是为了强调
        data['SIP'] = self.IP
        data['TIP'] = self.IP_TARGET
        data['SMAC'] = self.DEVICE_ID
        data['TMAC'] = DEVICE_ID_DICT['MB']
        data['CONTENT'] = 'Hi my name is Bill nice to meet u!'
        data['FLAG'] = 'COMM-SEND'
        print("Raw Data")
        print(data)
        dict2file(data, 'tmp.txt')
        self._encode_data(function_id=2, key=self.MAIN_COMMUNICATION_KEY)
        print("Encode Data")
        print(open('tmp.txt', 'rb').read())


    def commnication_get(self):
        print("接受的时候，接受方用主通信密钥解密数据")
        self._decode_data(function_id=2, key=self.MAIN_COMMUNICATION_KEY)
        dict = file2dict('tmp.txt')
        print('GET CONTENT')
        print(dict['CONTENT'])

    def _encode_data(self, function_id=1, key=None):
        if function_id == 1:
            cipher = PKCS1_v1_5.new(self.KP)
            cipher_text = cipher.encrypt(
                open('tmp.txt', 'rb').read()
            )
            with open('tmp.txt', 'wb') as f:
                f.write(cipher_text)
            return cipher_text
        elif function_id == 2:
            cipher = AESCipher(key.__str__())
            cipher_text = cipher.encrypt(
                open('tmp.txt', 'r').read()
            )
            with open('tmp.txt', 'wb') as f:
                f.write(cipher_text)
                f.close()
            return cipher_text

    def _decode_data(self, function_id=2, key=None):
        if function_id == 2:
            cipher = AESCipher(key.__str__())
            text = cipher.decrypt(
                open('tmp.txt', 'rb').read()
            )
            with open('tmp.txt', 'wb') as f:
                f.write(text)
                f.close()
        return text
