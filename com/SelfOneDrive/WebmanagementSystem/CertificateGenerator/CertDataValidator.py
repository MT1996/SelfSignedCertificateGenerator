
from dataclasses import fields
from com.SelfOneDrive.WebmanagementSystem.Domain.Model.CertData import CertData
from typing import Any
from flask import current_app

class CertDataValidator():

    @classmethod
    def dataObjectContainsAllInformation(self, certData: CertData) -> bool:
        for field in fields(certData):
            if getattr(certData, field.name) is None:
                return False
        
        return True
        