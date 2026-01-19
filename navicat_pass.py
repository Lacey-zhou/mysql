
import binascii
import xml.etree.ElementTree as ET

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

aes_key = b'libcckeylibcckey'
aes_iv = b'libcciv libcciv '


# 解密
def decrypt(upper_string):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=backend)
    decryptor = cipher.decryptor()

    encrypted_data = binascii.unhexlify(upper_string.lower())
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    except ValueError as e:
        print("Decryption error: Invalid padding bytes.")
        raise e
    return data.decode()


if __name__ == '__main__':
    # 本地文件地址
    xml_path_x = r'/password.ncx'
    # 格式化xml数据
    tree = ET.parse(xml_path_x)
    # 获取数据
    root_element = tree.getroot()
    for child in root_element:
        print('---------------------------------')
        print('ConnectionName:', child.attrib['ConnectionName'])
        print('Host:', child.attrib['Host'])
        print('Port:', child.attrib['Port'])
        print('UserName:', child.attrib['UserName'])
        print('source_Password:', child.attrib['Password'])
        print('Password:', decrypt(child.attrib['Password']))

