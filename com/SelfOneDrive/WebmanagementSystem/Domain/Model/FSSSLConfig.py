from dataclasses import dataclass
from .FSCertificate import FSCertificate
from .FSCSR import FSCSR
from .FSKey import FSKey

@dataclass
class SSLConfig():
    namespace: str
    fs_certificate: FSCertificate
    fs_csr: FSCSR
    fs_key: FSKey
