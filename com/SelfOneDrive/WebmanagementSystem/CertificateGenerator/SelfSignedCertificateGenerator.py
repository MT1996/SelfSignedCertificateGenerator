import datetime
from typing import List, Tuple
from datetime import datetime

from builtins import classmethod
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate, CertificateSigningRequest, CertificateBuilder
from cryptography.x509.extensions import ExtensionType
from cryptography.x509.name import NameAttribute
from cryptography.x509.oid import NameOID
from ..Config.Config import Config


class SelfSignedCertificateGenerator:

    def __init__(self) -> None:
        pass

    @classmethod
    def generate_Certificate_Authority(cls,
       ca_information: List[x509.NameAttribute],
       not_valid_after: datetime,
       extension: ExtensionType
    ) -> Tuple[rsa.RSAPrivateKey, Certificate]:
        privateKey = cls.generate_PrivateKey(
            Config.publicKeyExponent,
            Config.keySize
        )
        publicKey = cls.get_PublicKey_from_PrivateKey(privateKey)
        certificate: Certificate = CertificateBuilder().subject_name(
            x509.Name(ca_information)
        ).issuer_name(
            x509.Name(ca_information)
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            not_valid_after
        ).serial_number(
            x509.random_serial_number()
        ).public_key(
            publicKey
        ).add_extension(
            extension,
            True
        ).sign(privateKey, hashes.SHA256())

        return privateKey, certificate

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
        return x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name(
                csr_information
            )
        ).add_extension(
            additional_extensions,
            False
        ).sign(privateKey, hashes.SHA256())

    @classmethod
    def generate_SelfSignedServerCertificate(
        cls,
        csr: CertificateSigningRequest, 
        rootCACrt: Certificate, 
        rootCAKey: rsa.RSAPrivateKey,
        number_days_cert_valid: int,
        extension: ExtensionType
    ) -> Certificate:
        subject = csr.subject
        issuer = rootCACrt.subject
        publicKeyOfCrt = csr.public_key()
        signingPrivateKey = rootCAKey

        return CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            publicKeyOfCrt
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=number_days_cert_valid)
        ).add_extension(
            extension,
            False
        ).sign(signingPrivateKey, hashes.SHA256())
