import datetime
from typing import List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate, CertificateSigningRequest
from cryptography.x509.extensions import ExtensionType
from cryptography.x509.name import NameAttribute

class SelfSignedCertificateGenerator:

    def __init__(self) -> None:
        pass

    def generate_Certificate_Authority(
        privateKey: rsa.RSAPrivateKey,
        ca_information: List[x509.NameAttribute], 
        not_valid_before: datetime.datetime, 
        not_valid_after: datetime.datetime,
        serial_number: int,
        extensions: List[ExtensionType]
    ) -> Tuple[Certificate, rsa.RSAPrivateKey]:
        pass

    def generate_PrivateKey(public_exponent: int, key_size: int) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent,
            key_size
        )

    def get_PublicKey_from_PrivateKey(privateKey: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        return privateKey.public_key()

    def generate_CertificationSigningRequest(
        privateKey: rsa.RSAPrivateKey,
        csr_information: List[NameAttribute],
        additional_extensions: List[ExtensionType]
    ) -> CertificateSigningRequest:
        pass

    def generate_SelfSignedServerCertificate(
        csr: CertificateSigningRequest, 
        rootCACrt: Certificate, 
        rootCAKey: rsa.RSAPrivateKey
    ) -> Certificate:
        pass