import random
import gmpy2 as gmp

import sys
from collections import OrderedDict

sys.path.append('./config')

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from config import DEVICE_ID_DICT, dict2file, file2dict, COMMUNICATION_KEY_DICT, IPADDR_DICT
from aesFunc import AESCipher


class WallSystem(object):
    def __init__(self, NAME, DEVICE_ID, ks, IP):
        self.KS = ks
        self.IP = IP
        self.NAME = NAME
        self.DEVICE_ID = DEVICE_ID
        self.COMMUNICATION_KEY_CHAIN = {}  # 之后会改成AES密钥
        self.__third_send_flag = False

    def second_get(self):
        print("用私钥解密数据")
        self._decode_data()
        dict = file2dict('tmp.txt')
        print("Decode Data")
        print(dict)
        print("保存 KA,KB")
        self.COMMUNICATION_KEY_CHAIN['KA'] = dict['A_COMMUNICATION_KEY']
        self.COMMUNICATION_KEY_CHAIN['KB'] = COMMUNICATION_KEY_DICT['KB']
        if self.get_privilege('MA', 'MB'):
            # 获取权限
            print("允许访问")
            self.__third_send_flag = True
            return True
        else:
            return False

    def third_send(self):
        if self.__third_send_flag:
            data = OrderedDict()
            print("向B发送包含A地址的数据包，用KB加密")
            # 看上去是这么发，实际上IP地址本来就包含在数据包中，这么做只是为了强调
            data['SIP'] = self.IP
            data['TIP'] = IPADDR_DICT['MB']
            data['SMAC'] = self.DEVICE_ID
            data['TMAC'] = DEVICE_ID_DICT['MB']
            data['CONTENT'] = 'REQUEST FROM A; MY IP FOLLOWS'
            data['IP_TARGET'] = IPADDR_DICT['MA']
            data['FLAG'] = 'CER-3-INFORM'
            print("Raw Data")
            print(data)
            dict2file(data, 'tmp.txt')
            self._encode_data(method='AES', key=COMMUNICATION_KEY_DICT['KB'])
            self.__third_send_flag = False
            print("Encode Data")
            print(open('tmp.txt', 'rb').read())

    def sixth_send(self):
        print("用B的通信密钥解密数据包，保存主通信密钥")
        self._decode_data(2, self.COMMUNICATION_KEY_CHAIN['KB'])
        dict = file2dict('tmp.txt')
        self.COMMUNICATION_KEY_CHAIN['KC'] = dict['C_COMMUNICATION_KEY']
        print("Decode Data")
        print(dict)
        print("随后，将B的IP地址和主通信密钥用KA加密后发送给A")
        data = OrderedDict()
        # 看上去是这么发，实际上IP地址本来就包含在数据包中，这么做只是为了强调
        data['SIP'] = self.IP
        data['TIP'] = IPADDR_DICT['MA']
        data['SMAC'] = self.DEVICE_ID
        data['TMAC'] = DEVICE_ID_DICT['MA']
        data['CONTENT'] = 'IT IS B\' IP DECODE BY YOUR KEY '
        data['IP_TARGET'] = IPADDR_DICT['MB']
        data['KC'] = self.COMMUNICATION_KEY_CHAIN['KC']
        data['FLAG'] = 'CER-6-INFORM'
        print("Raw Data")
        print(data)
        dict2file(data, 'tmp.txt')
        self._encode_data(method='AES', key=self.COMMUNICATION_KEY_CHAIN['KA'])
        print("Encode Data")
        print(open('tmp.txt', 'rb').read())


    @staticmethod
    def get_privilege(A, B):
        '''
        在一个表中获取相应权限
        :return:
        '''
        return True

    def _decode_data(self, function_id=1, key=None):
        if function_id == 1:
            cipher = PKCS1_v1_5.new(self.KS)
            err = ""
            text = cipher.decrypt(
                open('tmp.txt', 'rb').read(), err
            )
            with open('tmp.txt', 'wb') as f:
                f.write(text)
            return text

        elif function_id == 2:
            cipher = AESCipher(key.__str__())
            text = cipher.decrypt(
                open('tmp.txt', 'rb').read()
            )
            with open('tmp.txt', 'wb') as f:
                f.write(text)
                f.close()
        return text

    def _encode_data(self, method, key):
        if method == 'AES':
            cipher = AESCipher(key.__str__())
            cipher_text = cipher.encrypt(
                open('tmp.txt', 'r').read()
            )
            with open('tmp.txt', 'wb') as f:
                f.write(cipher_text)
                f.close()
        return cipher_text
