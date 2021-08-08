from dataclasses import dataclass


@dataclass
class CertData():
    persistence_identifier: str
    country_name: str
    state_or_province_name: str
    local_city_name: str
    common_name: str
    organization_name: str
    organization_unit_name: str
    validation_range: int
