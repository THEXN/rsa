from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 读取PEM格式的私钥文件
with open('private_key.pem', 'rb') as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,  # 如果私钥有密码保护，需要提供密码
        backend=default_backend()
    )

# 获取公钥
public_key = private_key.public_key()

# 提取公钥参数
public_numbers = public_key.public_numbers()
n = public_numbers.n
e = public_numbers.e

print(f"模数 n: {n}")
print(f"公钥指数 e: {e}")
