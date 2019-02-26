import gmpy2 as gmp
import sys
import os
from Crypto.PublicKey import RSA
from collections import OrderedDict


def KP_KR_key_gener():
    from Crypto import Random
    generator = Random.new().read

    rsa = RSA.generate(2048, generator)

    private_pem = rsa.export_key()

    print("Gen PRI & PUB KEY FROM CA")
    f = open('../key_box/MY_KEY_PRI.pem', 'wb')
    f.write(private_pem)
    f.close()

    public_pem = rsa.publickey().export_key()
    f = open('../key_box/MY_KEY_PUB.pem', 'wb')
    f.write(public_pem)
    f.close()


def DEVICE_ID_DICT_gener():
    DEVICE_ID_DICT = {
        'MA': gmp.mpz(__import__('random').randint(0x1000000000, 0xFFFFFFFFFF)),
        'MB': gmp.mpz(__import__('random').randint(0x1000000000, 0xFFFFFFFFFF)),
        'WALL': gmp.mpz(__import__('random').randint(0x1000000000, 0xFFFFFFFFFF))
    }
    __import__('pickle').dump(DEVICE_ID_DICT,
                              open('D:\python_box\一篇论文的密码学复现\\final_project\config\DEVICE_ID.pkl', 'wb'))
    return DEVICE_ID_DICT


def COMMUNICATION_KEY_DICT_gen():
    COMMUNICATION_KEY_DICT = {
        'KA': gmp.mpz(__import__('random').randint(0xFFFFFF000, 0xFFFFFFFFFF)),
        'KB': gmp.mpz(__import__('random').randint(0xFFFFFF0000, 0xFFFFFFFFFF)),
        'KC': gmp.mpz(__import__('random').randint(0xFFFFFF0000, 0xFFFFFFFFFF)),
    }
    __import__('pickle').dump(COMMUNICATION_KEY_DICT,
                              open('D:\python_box\一篇论文的密码学复现\\final_project\config\COMMUNICATION_KEY.pkl', 'wb'))
    return COMMUNICATION_KEY_DICT


def IPADDR_DICT_gen():
    IPADDR_DICT = {
        'MA': __import__('iptools').ipv4.long2ip(__import__('random').randint(0, 0xFFFFFFFF)),
        'MB': __import__('iptools').ipv4.long2ip(__import__('random').randint(0, 0xFFFFFFFF)),
        'WALL': __import__('iptools').ipv4.long2ip(__import__('random').randint(0, 0xFFFFFFFF))
    }
    __import__('pickle').dump(IPADDR_DICT,
                              open('D:\python_box\一篇论文的密码学复现\\final_project\config\IPADDR.pkl', 'wb'))
    return IPADDR_DICT


def dict2file(dict, file_name):
    content = ""
    for key, value in dict.items():
        content += key.__str__() + '\t' + value.__str__() + '\n'
    with open(file_name, 'wb') as f:
        f.write(content.encode('utf8'))
        f.close()


def file2dict(file_name='tmp.txt'):
    dict = OrderedDict()
    with open(file_name, 'rb') as f:
        for line in f.readlines():
            line = line.decode('utf8')
            if line.__len__() > 3:
                if line.split('\t')[1].replace('\n', '').isdigit():
                    dict[line.split('\t')[0]] = gmp.mpz(line.split('\t')[1].replace('\n', ''))
                else:
                    dict[line.split('\t')[0]] = line.split('\t')[1].replace('\n', '')
    return dict


# DEVICE_ID_DICT_gener()
# COMMUNICATION_KEY_DICT_gen()
# IPADDR_DICT_gen()
DEVICE_ID_DICT = __import__('pickle').load(
    open('D:\python_box\一篇论文的密码学复现\\final_project\config\DEVICE_ID.pkl', 'rb'))
# print(DEVICE_ID_DICT)
COMMUNICATION_KEY_DICT = __import__('pickle').load(
    open('D:\python_box\一篇论文的密码学复现\\final_project\config\COMMUNICATION_KEY.pkl', 'rb'))
IPADDR_DICT = __import__('pickle').load(
    open('D:\python_box\一篇论文的密码学复现\\final_project\config\IPADDR.pkl', 'rb'))
