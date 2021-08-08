import datetime
from typing import List, Tuple

from builtins import classmethod
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate, CertificateSigningRequest, CertificateBuilder
from cryptography.x509.extensions import ExtensionType
from cryptography.x509.name import NameAttribute


class SelfSignedCertificateGenerator:

    def __init__(self) -> None:
        pass

    @classmethod
    def generate_Certificate_Authority(cls,
       privateKey: rsa.RSAPrivateKey,
       ca_information: List[x509.NameAttribute],
       not_valid_before: datetime.datetime,
       not_valid_after: datetime.datetime,
       serial_number: int,
       extension: ExtensionType
    ) -> Tuple[Certificate, rsa.RSAPrivateKey]:
        publicKey = privateKey.public_key()
        certificate = CertificateBuilder().subject_name(
            x509.Name(ca_information)
        ).issuer_name(
            x509.Name(ca_information)
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).serial_number(
            serial_number
        ).public_key(
            publicKey
        ).add_extension(
            extension
        ).sign(privateKey, hashes.SHA256())

        return ()

    @classmethod
    def generate_PrivateKey(cls, public_exponent: int, key_size: int) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent,
            key_size
        )

    @classmethod
    def get_PublicKey_from_PrivateKey(cls, privateKey: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
        return privateKey.public_key()

    @classmethod
    def generate_CertificationSigningRequest(
        cls,
        privateKey: rsa.RSAPrivateKey,
        csr_information: List[NameAttribute],
        additional_extensions: List[ExtensionType]
    ) -> CertificateSigningRequest:
        pass

    @classmethod
    def generate_SelfSignedServerCertificate(
        cls,
        csr: CertificateSigningRequest, 
        rootCACrt: Certificate, 
        rootCAKey: rsa.RSAPrivateKey
    ) -> Certificate:
        pass
