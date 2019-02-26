import random
import gmpy2 as gmp
import sys
from Crypto import Random
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from Crypto.PublicKey import RSA

sys.path.append('../')
sys.path.append('config')

from config import DEVICE_ID_DICT, COMMUNICATION_KEY_DICT, file2dict, dict2file, IPADDR_DICT
from M import MobileDevice
from backwall import WallSystem


kp = RSA.import_key(open('key_box/MY_KEY_PUB.pem', 'rb').read())
MA = MobileDevice(
    NAME='A',
    DEVICE_ID=DEVICE_ID_DICT['MA'],
    kp=kp,
    IP=IPADDR_DICT['MA']
)
MB = MobileDevice(
    NAME='B',
    DEVICE_ID=DEVICE_ID_DICT['MB'],
    kp=kp,
    IP=IPADDR_DICT['MB']
)
ks = RSA.import_key(open('key_box/MY_KEY_PRI.pem', 'rb').read())
WALL = WallSystem(
    NAME='WALL',
    DEVICE_ID=DEVICE_ID_DICT['WALL'],
    ks=ks,
    IP=IPADDR_DICT['WALL']
)
# A将包括A的身份识别标志、B的身份识别标志及通信密钥KA的访问请求报文，经
# 过公开密钥KP及RAS算法的加密，发送到关守系统上
print("--- ###  {}  ### ---".format("step1"))
MA.first_send()
print("--- ###  {}  ### ---".format("step2"))
WALL.second_get()
print("--- ###  {}  ### ---".format("step3"))
WALL.third_send()
print("--- ###  {}  ### ---".format("step4"))
MB.fourth_verify_and_send()
print("--- ###  {}  ### ---".format("step5"))
MB.fifth_send()
print("--- ###  {}  ### ---".format("step6"))
WALL.sixth_send()
print("--- ###  {}  ### ---".format("step7"))
MA.seventh_get()

print("--- ###  {}  ### ---".format("communication"))
MA.commnication_send()
MB.commnication_get()


