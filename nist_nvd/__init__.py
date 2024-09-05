from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import UUID4, BaseModel, ConfigDict, Field, field_validator
from aiohttp.client import ClientSession

# https://nvd.nist.gov/developers/products
CPES_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
# Documentation https://nvd.nist.gov/developers/data-sources
SOURCES_URL = "https://services.nvd.nist.gov/rest/json/source/2.0"

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

VALID_CVETAGS = ["disputed", "unsupported-when-assigned", "exclusively-hosted-service"]


class NVDAcceptanceLevel(BaseModel):
    """used in the NVDSources model"""

    description: str
    last_modified: datetime = Field(
        alias="lastModified", serialization_alias="lastModified"
    )
    model_config = ConfigDict(extra="forbid")


class NVDResponse(BaseModel):
    # JSON Schema: https://csrc.nist.gov/schema/nvd/api/2.0/source_api_json_2.0.schema
    results_per_page: int = Field(
        alias="resultsPerPage", serialization_alias="resultsPerPage"
    )
    start_index: int = Field(alias="startIndex", serialization_alias="startIndex")
    total_results: int = Field(alias="totalResults", serialization_alias="totalResults")
    format: str
    version: str
    timestamp: datetime
    model_config = ConfigDict(extra="forbid")


class NVDSource(BaseModel):
    name: str
    contact_email: str = Field(alias="contactEmail", serialization_alias="contactEmail")
    last_modified: datetime = Field(
        alias="lastModified", serialization_alias="lastModified"
    )
    created: datetime
    source_identifers: List[str] = Field(
        list(), alias="sourceIdentifiers", serialization_alias="sourceIdentifiers"
    )
    v4_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="v4AcceptanceLevel", serialization_alias="v4AcceptanceLevel"
    )
    v3_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="v3AcceptanceLevel", serialization_alias="v3AcceptanceLevel"
    )
    v2_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="v2AcceptanceLevel", serialization_alias="v2AcceptanceLevel"
    )
    cwe_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="cweAcceptanceLevel", serialization_alias="cweAcceptanceLevel"
    )
    model_config = ConfigDict(extra="forbid")


class NVDCPETitle(BaseModel):
    title: str
    lang: str


class NVDReference(BaseModel):
    ref: Optional[str] = None
    type: Optional[str] = None


class NVDCPEDeprecation(BaseModel):
    cpe_name: Optional[str] = Field(
        None, alias="cpeName", serialization_alias="cpeName"
    )
    cpe_name_id: UUID4 = Field(alias="cpeNameId", serialization_alias="cpeNameId")

    @field_validator("cpe_name", mode="before")
    def validate_cpe_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if len(value.split(":")) != 13:
            raise ValueError("CPE Name must be 13 colon-separated values")
        return value


class NVDCPE(BaseModel):
    deprecated: Optional[bool] = False
    lang: Optional[str] = None
    cpe_name: Optional[str] = Field(
        None, alias="cpeName", serialization_alias="cpeName"
    )
    cpe_name_id: UUID4 = Field(alias="cpeNameId", serialization_alias="cpeNameId")
    last_modified: Optional[datetime] = Field(
        None, alias="lastModified", serialization_alias="lastModified"
    )
    created: Optional[datetime] = None
    titles: List[NVDCPETitle] = []
    refs: List[NVDReference] = []
    deprecated_by: List[NVDCPEDeprecation] = Field(
        list(), alias="deprecatedBy", serialization_alias="deprecatedBy"
    )
    deprecates: List[NVDCPEDeprecation] = []
    model_config = ConfigDict(extra="forbid")


class NVDProduct(BaseModel):
    cpe: NVDCPE


class NVDCPEs(NVDResponse):
    products: List[NVDProduct]
    model_config = ConfigDict(extra="forbid")


class NVDSources(NVDResponse):
    sources: List[NVDSource]
    model_config = ConfigDict(extra="forbid")


class NVDDescription(BaseModel):
    lang: str
    value: str
    model_config = ConfigDict(extra="forbid")


class NVDWeakness(BaseModel):
    source: str
    type: str
    description: List[NVDDescription]
    model_config = ConfigDict(extra="forbid")


class CVSSV2Data(BaseModel):
    version: str = Field(alias="version", serialization_alias="version")
    vector_string: str = Field(alias="vectorString", serialization_alias="vectorString")
    access_vector: str = Field(alias="accessVector", serialization_alias="accessVector")
    access_complexity: str = Field(
        alias="accessComplexity", serialization_alias="accessComplexity"
    )
    authentication: str = Field(
        alias="authentication", serialization_alias="authentication"
    )
    confidentiality_impact: str = Field(
        alias="confidentialityImpact", serialization_alias="confidentialityImpact"
    )
    integrity_impact: str = Field(
        alias="integrityImpact", serialization_alias="integrityImpact"
    )
    availability_impact: str = Field(
        alias="availabilityImpact", serialization_alias="availabilityImpact"
    )
    base_score: float = Field(alias="baseScore", serialization_alias="baseScore")
    model_config = ConfigDict(extra="forbid")


class cvssMetricV2(BaseModel):
    source: str
    type: str
    cvss_data: CVSSV2Data = Field(alias="cvssData", serialization_alias="cvssData")
    base_severity: str = Field(alias="baseSeverity", serialization_alias="baseSeverity")
    exploitability_score: float = Field(
        alias="exploitabilityScore", serialization_alias="exploitabilityScore"
    )
    impact_score: float = Field(alias="impactScore", serialization_alias="impactScore")
    ac_insuf_info: bool = Field(alias="acInsufInfo", serialization_alias="acInsufInfo")
    obtain_all_privilege: bool = Field(
        alias="obtainAllPrivilege", serialization_alias="obtainAllPrivilege"
    )
    obtain_user_privilege: bool = Field(
        alias="obtainUserPrivilege", serialization_alias="obtainUserPrivilege"
    )
    obtain_other_privilege: bool = Field(
        alias="obtainOtherPrivilege", serialization_alias="obtainOtherPrivilege"
    )
    user_interaction_required: Optional[bool] = Field(
        None,
        alias="userInteractionRequired",
        serialization_alias="userInteractionRequired",
    )

    model_config = ConfigDict(extra="forbid")


class cvssMetricV3(BaseModel):
    source: Optional[str] = None
    type: Optional[str] = None
    exploitability_score: float = Field(
        alias="exploitabilityScore", serialization_alias="exploitabilityScore"
    )
    impact_score: float = Field(alias="impactScore", serialization_alias="impactScore")
    cvss_data: Dict[str, Any] = Field(alias="cvssData", serialization_alias="cvssData")
    model_config = ConfigDict(extra="forbid")


class cvssMetricV4(BaseModel):
    source: str
    type: str
    cvss_data: Dict[str, Any] = Field(alias="cvssData", serialization_alias="cvssData")

    model_config = ConfigDict(extra="forbid")


class NVDMetrics(BaseModel):
    cvss_metric_v2: Optional[List[cvssMetricV2]] = Field(
        None, alias="cvssMetricV2", serialization_alias="cvssMetricV2"
    )
    cvss_metric_v3: Optional[List[cvssMetricV3]] = Field(
        None, alias="cvssMetricV3", serialization_alias="cvssMetricV3"
    )
    cvss_metric_v30: Optional[List[cvssMetricV3]] = Field(
        None, alias="cvssMetricV30", serialization_alias="cvssMetricV30"
    )
    cvss_metric_v31: Optional[List[cvssMetricV3]] = Field(
        None, alias="cvssMetricV31", serialization_alias="cvssMetricV31"
    )
    cvss_metric_v4: Optional[List[cvssMetricV4]] = Field(
        None, alias="cvssMetricV4", serialization_alias="cvssMetricV4"
    )
    cvss_metric_v40: Optional[List[cvssMetricV4]] = Field(
        None, alias="cvssMetricV40", serialization_alias="cvssMetricV40"
    )
    model_config = ConfigDict(extra="forbid")


class VendorComment(BaseModel):
    organization: str
    comment: str
    last_modified: Optional[datetime] = Field(
        None, alias="lastModified", serialization_alias="lastModified"
    )

    model_config = ConfigDict(extra="forbid")


class CVETags(BaseModel):
    source_identifier: Optional[str] = Field(
        None, alias="sourceIdentifier", serialization_alias="sourceIdentifier"
    )
    tags: List[str] = list()
    model_config = ConfigDict(extra="forbid")


class NVDVulnerabilityData(BaseModel):
    id: Optional[str] = None
    source_identifier: str = Field(
        alias="sourceIdentifier", serialization_alias="sourceIdentifier"
    )
    published: datetime
    last_modified: datetime = Field(
        alias="lastModified", serialization_alias="lastModified"
    )
    vuln_status: str = Field(alias="vulnStatus", serialization_alias="vulnStatus")
    cve_tags: List[CVETags] = Field(
        list(), alias="cveTags", serialization_alias="cveTags"
    )
    descriptions: List[NVDDescription] = []
    references: List[NVDReference] = []
    weaknesses: List[NVDWeakness] = []
    configurations: List[Dict[str, Any]] = Field(list())
    metrics: Optional[NVDMetrics] = None
    evaluator_comment: Optional[str] = Field(
        None, alias="evaluatorComment", serialization_alias="evaluatorComment"
    )
    evaluator_solution: Optional[str] = Field(
        None, alias="evaluatorSolution", serialization_alias="evaluatorSolution"
    )
    evaluator_impact: Optional[str] = Field(
        None, alias="evaluatorImpact", serialization_alias="evaluatorImpact"
    )
    vendor_comments: List[VendorComment] = Field(
        list(), alias="vendorComments", serialization_alias="vendorComments"
    )

    cisa_exploit_add: Optional[datetime] = Field(
        None, alias="cisaExploitAdd", serialization_alias="cisaExploitAdd"
    )
    cisa_action_due: Optional[datetime] = Field(
        None, alias="cisaActionDue", serialization_alias="cisaActionDue"
    )
    cisa_required_action: Optional[str] = Field(
        None, alias="cisaRequiredAction", serialization_alias="cisaRequiredAction"
    )
    cisa_vulnerability_name: Optional[str] = Field(
        None, alias="cisaVulnerabilityName", serialization_alias="cisaVulnerabilityName"
    )
    model_config = ConfigDict(extra="forbid")


class NVDVulnerability(BaseModel):
    cve: NVDVulnerabilityData
    model_config = ConfigDict(extra="forbid")


class NVDVulnerabilities(NVDResponse):
    vulnerabilities: List[NVDVulnerability]
    model_config = ConfigDict(extra="forbid")


class NVD:
    def __init__(
        self,
        api_key: Optional[str] = None,
        client_session: Optional[ClientSession] = None,
    ):
        self.api_key = api_key
        if client_session is not None:
            self.client = client_session
        else:
            self.client = ClientSession()

    async def get_sources(
        self,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        results_per_page: int = 1000,
        source_identifier: Optional[str] = None,
        start_index: int = 0,  # This parameter specifies the index of the first source record to be returned in the response data. The index is zero-based, meaning the first source record is at index zero.
    ) -> NVDSources:
        """The Source API is used to easily retrieve detailed information on the organizations that provide the data contained in the NVD dataset.

        The API is updated whenever a new source is added, or an existing source is modified. Data sources change so infrequently that users interested in this information may choose to limit their requests to once per day.
        """

        query: Dict[str, int | str | None] = {
            "resultsPerPage": str(results_per_page),
            "startIndex": str(start_index),
        }
        if last_mod_start_date is not None:
            # TODO: validate the date format
            query["lastModStartDate"] = last_mod_start_date.isoformat()
        if last_mod_end_date is not None:
            # TODO: validate the date format
            query["lastModEndDate"] = last_mod_end_date.isoformat()
        if source_identifier is not None:
            query["sourceIdentifier"] = source_identifier

        headers = {"user-agent": "nist_nvd python client"}

        if self.api_key is not None:
            headers["apiKey"] = self.api_key

        async with self.client.get(
            SOURCES_URL, headers=headers, params=query
        ) as response:
            response.raise_for_status()
            return NVDSources.model_validate_json(await response.text())

    async def get_products(
        self,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        source_identifier: Optional[str] = None,
        results_per_page: int = 1000,
        start_index: int = 0,  # This parameter specifies the index of the first source record to be returned in the response data. The index is zero-based, meaning the first source record is at index zero.
        cpe_name_id: Optional[str] = None,
        # This parameter returns CPE Names that exist in the Official CPE Dictionary, based on the value of {match string}.
        # A CPE Name is a string of characters comprised of 13 colon separated values that describe a product. In CPEv2.3 the first two values are always “cpe” and “2.3”. The 11 values that follow are referred to as the CPE components.
        cpe_match_string: Optional[str] = None,
        keyword_exact_match: Optional[bool] = False,
        keyword_search: Optional[str] = None,
        match_criteria_id: Optional[str] = None,
    ) -> NVDCPEs:
        """ """

        class ProductRequest(BaseModel):
            cpe_name_id: Optional[UUID4] = Field(
                None, alias="cpeNameId", serialization_alias="cpeNameId"
            )
            cpe_match_string: Optional[str] = Field(
                None, alias="cpeMatchString", serialization_alias="cpeMatchString"
            )
            keyword_exact_match: Optional[bool] = Field(
                False,
                alias="keywordExactMatch",
                serialization_alias="keywordExactMatch",
            )
            match_criteria_id: Optional[UUID4] = Field(
                None, alias="matchCriteriaId", serialization_alias="matchCriteriaId"
            )

            @field_validator("cpe_match_string", mode="before")
            def validate_cpe_match_string(cls, value: Optional[str]) -> Optional[str]:
                if value is None:
                    return value
                if len(value.split(":")) != 13:
                    raise ValueError(
                        "CPE Match String must be 13 colon-separated values"
                    )
                return value

        ProductRequest.model_validate(
            {
                "cpeNameId": cpe_name_id,
                "cpe_match_string": cpe_match_string,
                "keyword_exact_match": keyword_exact_match,
                "match_criteria_id": match_criteria_id,
            }
        )

        query: Dict[str, int | str | None] = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        if last_mod_start_date is not None:
            query["lastModStartDate"] = last_mod_start_date.isoformat()
        if last_mod_end_date is not None:
            query["lastModEndDate"] = last_mod_end_date.isoformat()
        if source_identifier is not None:
            query["sourceIdentifier"] = source_identifier
        if keyword_exact_match:
            query["keywordExactMatch"] = ""
        if keyword_search is not None:
            query["keywordSearch"] = keyword_search
        if match_criteria_id is not None:
            query["matchCriteriaId"] = match_criteria_id
        if cpe_name_id is not None:
            query["cpeNameId"] = cpe_name_id
        if cpe_match_string is not None:
            query["cpeMatchString"] = cpe_match_string

        headers = {"user-agent": "nist_nvd python client"}

        if self.api_key is not None:
            headers["apiKey"] = self.api_key

        async with self.client.get(CPES_URL, headers=headers, params=query) as response:
            response.raise_for_status()
            return NVDCPEs.model_validate_json(await response.text())

    async def get_vulnerabilities(
        self,
        results_per_page: int = 1000,
        start_index: int = 0,  # This parameter specifies the index of the first source record to be returned in the response data. The index is zero-based, meaning the first source record is at index zero.
        source_identifier: Optional[str] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        version_end: Optional[str] = None,
        version_end_type: Optional[str] = None,
        virtual_match_string: Optional[str] = None,
        version_start: Optional[str] = None,
        version_start_type: Optional[str] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        not_rejected: Optional[bool] = False,
        cpe_name: Optional[str] = None,
        cve_id: Optional[str] = None,
        cve_tag: Optional[str] = None,
        cvss_v2_metrics: Optional[str] = None,
        cvss_v3_metrics: Optional[str] = None,
        cvss_v4_metrics: Optional[str] = None,
        cvss_v2_severity: Optional[str] = None,
        cvss_v3_severity: Optional[str] = None,
        cvss_v4_severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        has_cert_alerts: Optional[bool] = False,
        has_cert_notes: Optional[bool] = False,
        has_kev: Optional[bool] = False,
        has_oval: Optional[bool] = False,
        is_vulnerable: Optional[bool] = False,
        keyword_exact_match: Optional[str] = None,
        keyword_search: Optional[str] = None,
    ) -> NVDVulnerabilities:
        if [
            cvss_v2_metrics,
            cvss_v3_metrics,
            cvss_v4_metrics,
        ].count(None) < 2:
            raise ValueError("Only one CVSS metric may be provided")

        headers = {"user-agent": "nist_nvd python client"}

        if self.api_key is not None:
            headers["apiKey"] = self.api_key

        query = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        if last_mod_start_date is not None:
            query["lastModStartDate"] = last_mod_start_date.isoformat()
        if last_mod_end_date is not None:
            query["lastModEndDate"] = last_mod_end_date.isoformat()
        if pub_start_date is not None:
            query["pubStartDate"] = last_mod_start_date.isoformat()
        if pub_end_date is not None:
            query["pubEndDate"] = last_mod_end_date.isoformat()
        if source_identifier is not None:
            query["sourceIdentifier"] = source_identifier
        if cve_id is not None:
            query["cveId"] = cve_id
        if cve_tag is not None:
            if cve_tag not in VALID_CVETAGS:
                raise ValueError(
                    "Invalid cveTag, should be one of {}".format(
                        ",".join(VALID_CVETAGS)
                    )
                )
            query["cveTag"] = cve_tag
        if cwe_id is not None:
            query["cweId"] = cwe_id

        if version_end is not None:
            query["versionEnd"] = version_end
            if version_end_type is not None:
                if version_end_type not in ["including", "excluding"]:
                    raise ValueError(
                        "Invalid versionEndType, should be one of including, excluding"
                    )
                query["versionEndType"] = version_end_type
            else:
                raise ValueError("versionEndType must be provided if versionEnd is")
            if virtual_match_string is not None:
                query["virtualMatchString"] = virtual_match_string
            else:
                raise ValueError("virtualMatchString must be provided if versionEnd is")
        if version_start is not None:
            query["versionStart"] = version_start
            if version_start_type is not None:
                if version_start_type not in ["including", "excluding"]:
                    raise ValueError(
                        "Invalid versionStartType, should be one of including, excluding"
                    )
                query["versionStartType"] = version_start_type
            else:
                raise ValueError("versionStartType must be provided if versionStart is")
            if virtual_match_string is not None:
                query["virtualMatchString"] = virtual_match_string
            else:
                raise ValueError(
                    "virtualMatchString must be provided if versionStart is"
                )

        if has_cert_alerts:
            query["hasCertAlerts"] = ""
        if has_cert_notes:
            query["hasCertNotes"] = ""
        if has_kev:
            query["hasKev"] = ""
        if has_oval:
            query["hasOval"] = ""
        if not_rejected:
            query["notRejected"] = ""

        if is_vulnerable:
            query["isVulnerable"] = ""
            if cpe_name is None:
                raise ValueError("CPE Name must be provided if isVulnerable is True")
        if cpe_name is not None:
            if len(cpe_name.split(":")) != 13:
                raise ValueError("CPE Name must be 13 colon-separated values")
            query["cpeName"] = cpe_name

        if keyword_exact_match is not None:
            query["keywordExactMatch"] = keyword_exact_match
        if keyword_search is not None:
            query["keywordSearch"] = keyword_search

        if cvss_v2_metrics is not None:
            query["cvssV2Metrics"] = cvss_v2_metrics
        elif cvss_v3_metrics is not None:
            query["cvssV3Metrics"] = cvss_v3_metrics
        elif cvss_v4_metrics is not None:
            query["cvssV4Metrics"] = cvss_v4_metrics
        if cvss_v2_severity is not None:
            valid_cvss_v2_severity = ["LOW", "MEDIUM", "HIGH"]
            if cvss_v2_severity not in valid_cvss_v2_severity:
                raise ValueError(
                    "Invalid cvssV2Severity, should be one of {}".format(
                        ",".join(valid_cvss_v2_severity)
                    )
                )
            query["cvssV2Severity"] = cvss_v2_severity
        if cvss_v3_severity is not None:
            valid_cvss_v3_severity = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if cvss_v3_severity not in valid_cvss_v3_severity:
                raise ValueError(
                    "Invalid cvssV3Severity, should be one of {}".format(
                        ",".join(valid_cvss_v3_severity)
                    )
                )
            query["cvssV3Severity"] = cvss_v3_severity
        if cvss_v4_severity is not None:
            valid_cvss_v4_severity = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if cvss_v4_severity not in valid_cvss_v4_severity:
                raise ValueError(
                    "Invalid cvssV4Severity, should be one of {}".format(
                        ",".join(valid_cvss_v4_severity)
                    )
                )
            query["cvssV4Severity"] = cvss_v4_severity

        async with self.client.get(
            CVE_API_URL, headers=headers, params=query
        ) as response:
            response.raise_for_status()
            text = await response.text()
            try:
                return NVDVulnerabilities.model_validate_json(text)
            except Exception as error:
                # print(text)
                raise error
