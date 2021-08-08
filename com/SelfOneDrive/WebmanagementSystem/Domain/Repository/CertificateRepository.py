from typing import List
from builtins import classmethod
from cryptography.x509 import Certificate
from com.SelfOneDrive.WebmanagementSystem import FileSystemProvider


class CertificateRepository():

    filesystemProvider: FileSystemProvider = FileSystemProvider()

    def __init__(self):
        pass

    @classmethod
    def persistAll(cls, persistence_identifiers: List[str], certificates: List[Certificate]) -> bool:
        for persistence_identifier, certificate in zip(persistence_identifiers, certificates):
            if not cls.persistOne(persistence_identifier, certificate):
                return False
        return True

    @classmethod
    def persistOne(cls, persistence_identifier: str, certificate: Certificate) -> bool:
        return cls.filesystemProvider.createCertEntry(persistence_identifier, certificate)
