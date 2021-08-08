from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.base import Certificate, CertificateBuilder, CertificateSigningRequest, \
    load_pem_x509_certificate, load_pem_x509_csr
from cryptography.x509.oid import NameOID


def generate_CA():
    public_exponent = 65537
    key_size = 4096
    privateKey: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent, 
        key_size
    )
    publicKey = privateKey.public_key()
    certificate = CertificateBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Niedersachsen"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braunschweig"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"selfonedrive.home-webserver.de"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SelfOneDrive Corp. Root CA'),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Development')
            ]
        )
    ).issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Niedersachsen"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braunschweig"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"selfonedrive.home-webserver.de"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SelfOneDrive Corp. Root CA'),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Development')
            ]
        )
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).serial_number(
        x509.random_serial_number()
    ).public_key(
        publicKey
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(
        privateKey,
        hashes.SHA256(),
        default_backend()
    )
    print(isinstance(certificate, x509.Certificate))

    with open("rootCA.key", "wb") as rootCA:
        rootCA.write(
            privateKey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(b"myRootPassword")
            )
        )
    
    with open("rootCA.crt", "wb") as rootCA:
        rootCA.write(
            certificate.public_bytes(
                serialization.Encoding.PEM
            )
        )

def generate_private_key():
    public_exponent = 65537
    key_size = 4096
    key = rsa.generate_private_key(
        public_exponent, 
        key_size
    )

    with open("privateKeyForSelfOneDrive.key", "wb") as keyFile:
        keyFile.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            )
        )

def generate_CSR_with_key(key: rsa.RSAPrivateKey):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Niedersachsen"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braunschweig"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"selfonedrive.home-webserver.de"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SelfOneDrive Corp.")
            ]
        )
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"selfonedrive.home-webserver.de"),
            x509.DNSName(u"www.selfonedrive.home-webserver.de")
        ]),
        False
    ).sign(key, hashes.SHA256())

    with open("CSRForSelfOneDrive.csr", "wb") as csrFile:
        csrFile.write(
            csr.public_bytes(
                serialization.Encoding.PEM
            )
        )

def generate_Certificate_from_CSR_CACrt_And_CAkey(csr: CertificateSigningRequest, rootCACrt: Certificate, rootCAKey: rsa.RSAPrivateKey):
    subject = csr.subject
    issuer = rootCACrt.subject
    publicKeyOfCrt = csr.public_key()
    signingPrivateKey = rootCAKey

    cert = CertificateBuilder().subject_name(
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
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName(u"selfonedrive.home-webserver.de"),
                x509.DNSName(u"www.selfonedrive.home-webserver.de")
            ]
        ),
        critical=False
    ).sign(signingPrivateKey, hashes.SHA256())

    with open("CertificateForSelfOneDrive.crt", "wb") as CertFile:
        CertFile.write(
            cert.public_bytes(
                serialization.Encoding.PEM
            )
        )

if __name__ == "__main__":
    generate_CA()

    generate_private_key()

    bytes_of_key = None
    with open("privateKeyForSelfOneDrive.key", "rb") as keyFile:
        bytes_of_key = keyFile.read()
    myPrivateKey = load_pem_private_key(bytes_of_key, None)

    generate_CSR_with_key(myPrivateKey)

    bytes_of_Csr = None
    with open("CSRForSelfOneDrive.csr", "rb") as CsrFile:
        bytes_of_Csr = CsrFile.read()
    
    myCSR = load_pem_x509_csr(bytes_of_Csr)

    bytes_of_CACrt = None
    with open("rootCA.crt", "rb") as rootCA:
        bytes_of_CACrt = rootCA.read()
    
    rootCACrt = load_pem_x509_certificate(bytes_of_CACrt)

    bytes_of_CAkey = None
    with open("rootCA.key", "rb") as keyFile:
        bytes_of_CAkey = keyFile.read()
    
    rootCAKey = load_pem_private_key(bytes_of_CAkey, b"myRootPassword")

    generate_Certificate_from_CSR_CACrt_And_CAkey(myCSR, rootCACrt, rootCAKey)