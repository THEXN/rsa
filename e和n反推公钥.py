from Crypto.PublicKey import RSA
import base64
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder as der_encoder

class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer())
    )

def create_pem_public_key(e, n):
    # 创建一个包含e和n的ASN.1结构
    rsa_pub_key = RSAPublicKey()
    rsa_pub_key.setComponentByName('modulus', n)
    rsa_pub_key.setComponentByName('publicExponent', e)

    # 编码为DER格式
    der_encoded = der_encoder.encode(rsa_pub_key)

    # Base64编码
    b64_encoded = base64.b64encode(der_encoded).decode('utf-8')

    # 构建PEM格式
    pem_public_key = f"-----BEGIN RSA PUBLIC KEY-----\n{b64_encoded}\n-----END RSA PUBLIC KEY-----"

    return pem_public_key

# 示例使用
e = 9647291  # 公钥指数
n = int('22708078815885011462462049064339185898712439277226831073457888403129378547350292420267016551819052430779004755846649044001024141485283286483130702616057274698473611149508798869706347501931583117632710700787228016480127677393649929530416598686027354216422565934459015161927613607902831542857977859612596282353679327773303727004407262197231586324599181983572622404590354084541788062262164510140605868122410388090174420147752408554129789760902300898046273909007852818474030770699647647363015102118956737673941354217692696044969695308506436573142565573487583507037356944848039864382339216266670673567488871508925311154801')  # 模数n，这里应替换为实际的数值

print(create_pem_public_key(e, n))