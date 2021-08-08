from typing import List
from builtins import classmethod
from cryptography.x509.base import rsa
from com.SelfOneDrive.WebmanagementSystem import FileSystemProvider


class KeyRepository():

    filesystemProvider: FileSystemProvider = FileSystemProvider()

    def __init__(self):
        pass

    @classmethod
    def persistAll(cls, persistence_identifiers: List[str], privateKeys: List[rsa.RSAPrivateKey]) -> bool:
        for persistence_identifier, privateKey in zip(persistence_identifiers, privateKeys):
            if not cls.persistOne(persistence_identifier, privateKey):
                return False
        return True

    @classmethod
    def persistOne(cls, persistence_identifier: str, privateKey: rsa.RSAPrivateKey) -> bool:
        return cls.filesystemProvider.createKeyEntry(persistence_identifier, privateKey)
