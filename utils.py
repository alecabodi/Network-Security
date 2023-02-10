import base64
import json
import math
import uuid
from hashlib import sha256

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def encode_base64(content):
    if type(content) == str:
        content = content.encode('utf8')

    return base64.urlsafe_b64encode(content).decode('utf8').strip("=")


def my_to_bytes(n):
    return n.to_bytes(math.ceil(n.bit_length() / 8.0), 'big')


def hash256(content):
    return sha256(content.encode('utf8')).digest()


def encodeDER(certificate):
    return certificate.public_bytes(Encoding.DER)


def encodePEM(certificate):
    return certificate.public_bytes(Encoding.PEM)


class JOSE:

    def __init__(self):
        self.private_key = self.get_private_key()
        self.public_key = self.get_public_key(self.private_key)

        self.cert_private_key = self.get_cert_private_key()

    def get_private_key(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    def get_public_key(self, private_key):
        return private_key.public_key()

    def get_cert_private_key(self):

        cert_private_key = self.get_private_key()

        with open("private_key.pem", "wb") as file:
            file.write(cert_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                      format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                      encryption_algorithm=serialization.NoEncryption()))
            file.close()

        return cert_private_key

    def get_protected_header(self, alg, nonce, url, key_type):
        key = None

        if key_type == "jwk":
            key = self.get_jwk()

        if key_type == "kid":
            key = self.get_kid()

        return {"alg": alg, "nonce": nonce, "url": url, f"{key_type}": key}

    def get_jwk(self):
        jwk = {"kty": "RSA",
               "alg": "RS256",
               "n": encode_base64(my_to_bytes(self.public_key.public_numbers().n)),
               "e": encode_base64(my_to_bytes(self.public_key.public_numbers().e)),
               "kid": str(uuid.uuid4())}

        return jwk

    def get_kid(self):
        from client import kid
        return kid

    def get_jws(self, payload, nonce, url, key_type):
        protected_header_tmp = self.get_protected_header("RS256", nonce, url, key_type)
        protected_header = encode_base64(json.dumps(protected_header_tmp))

        if payload == "":
            payload = encode_base64(payload)
        else:
            payload = encode_base64(json.dumps(payload))

        m = f"{protected_header}.{payload}".encode('utf8')

        signature_tmp = self.private_key.sign(m, padding=padding.PKCS1v15(), algorithm=hashes.SHA256())
        signature = encode_base64(signature_tmp)

        jws = {
            "protected": protected_header,
            "payload": payload,
            "signature": signature
        }

        return jws

    def get_csr(self, domains):

        csr = x509.CertificateSigningRequestBuilder() \
            .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"CA-CERTIFICATE")])) \
            .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]), critical=False) \
            .sign(self.cert_private_key, hashes.SHA256())

        return encode_base64(encodeDER(csr))


def get_auth_key(token, jwk_thumbprint):
    return f"{token}.{encode_base64(hash256(jwk_thumbprint))}"


def load_pem_x509(cert_tmp):
    return x509.load_pem_x509_certificate(cert_tmp, backend=default_backend())
