import asyncio
from datetime import datetime
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Literal, Optional, Set, Union

from aiohttp import ClientTimeout
from loguru import logger
from pydantic import UUID4, BaseModel, ConfigDict, Field, field_validator
from aiohttp.client import ClientSession
import aiohttp.client_exceptions


if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        pass


from .config import Config

# https://nvd.nist.gov/developers/products
CPES_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
# Documentation https://nvd.nist.gov/developers/data-sources
SOURCES_URL = "https://services.nvd.nist.gov/rest/json/source/2.0"

CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

VALID_CVETAGS = ["disputed", "unsupported-when-assigned", "exclusively-hosted-service"]


class WriteFileMixin:
    """Allows a model to be written to a file easily"""

    def model_dump_json(
        self,
        *,
        indent: Optional[int] = None,
        include: Union[Set[int], Set[str], Dict[int, Any], Dict[str, Any], None] = None,
        exclude: Union[Set[int], Set[str], Dict[int, Any], Dict[str, Any], None] = None,
        context: Optional[Any] = None,
        by_alias: bool = False,
        exclude_unset: bool = False,
        exclude_defaults: bool = False,
        exclude_none: bool = False,
        round_trip: bool = False,
        warnings: Union[bool, Literal["none", "warn", "error"]] = True,
        serialize_as_any: bool = False,
    ) -> str:
        raise NotImplementedError(
            "This method must be implemented in the subclass by pydantic.BaseModel"
        )

    def write_file(self, filename: Union[str, Path]) -> None:
        """Write the model to a JSON file, including None values"""
        if not Path(filename).parent.exists():
            logger.debug(f"Parent directory for {filename} doesn't exist, creating...")
            Path(filename).parent.mkdir(parents=True)
        with open(filename, "w") as f:
            logging.debug(f"writing to {filename}")
            f.write(
                self.model_dump_json(
                    indent=4,
                    exclude_none=True,
                    exclude_unset=False,
                    exclude_defaults=True,
                    by_alias=True,  # so it uses the aliases we told it to
                )
            )


class NVDAcceptanceLevel(BaseModel):
    """used in the NVDSources model"""

    description: str
    last_modified: datetime = Field(alias="lastModified")
    model_config = ConfigDict(extra="forbid")


class NVDResponse(BaseModel, WriteFileMixin):
    # JSON Schema: https://csrc.nist.gov/schema/nvd/api/2.0/source_api_json_2.0.schema
    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    format: str
    version: str
    timestamp: datetime
    model_config = ConfigDict(extra="forbid")


class NVDSource(BaseModel):
    name: str
    contact_email: str = Field(alias="contactEmail")
    last_modified: datetime = Field(alias="lastModified")
    created: datetime
    source_identifers: List[str] = Field(list(), alias="sourceIdentifiers")
    v4_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="v4AcceptanceLevel"
    )
    v3_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="v3AcceptanceLevel"
    )
    v2_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="v2AcceptanceLevel"
    )
    cwe_acceptance_level: Optional[NVDAcceptanceLevel] = Field(
        None, alias="cweAcceptanceLevel"
    )
    model_config = ConfigDict(extra="forbid")


class NVDCPETitle(BaseModel):
    title: str
    lang: str
    model_config = ConfigDict(extra="forbid")


class NVDReference(BaseModel):
    ref: Optional[str] = Field(None)
    type: Optional[str] = Field(None)
    source: Optional[str] = Field(None)
    url: Optional[str] = Field(None)
    tags: List[str] = Field(list())
    model_config = ConfigDict(extra="forbid")


class NVDCPEDeprecation(BaseModel):
    cpe_name: Optional[str] = Field(None, alias="cpeName")
    cpe_name_id: UUID4 = Field(alias="cpeNameId")
    model_config = ConfigDict(extra="forbid")

    @field_validator("cpe_name", mode="before")
    def validate_cpe_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if len(value.split(":")) != 13:
            raise ValueError("CPE Name must be 13 colon-separated values")
        return value


class NVDCPE(BaseModel):
    cpe_name_id: UUID4 = Field(alias="cpeNameId")
    cpe_name: Optional[str] = Field(None, alias="cpeName")
    created: Optional[datetime] = None
    deprecated_by: List[NVDCPEDeprecation] = Field(list(), alias="deprecatedBy")
    deprecated: Optional[bool] = False
    deprecates: List[NVDCPEDeprecation] = []
    lang: Optional[str] = None
    last_modified: Optional[datetime] = Field(None, alias="lastModified")
    refs: List[NVDReference] = []
    titles: List[NVDCPETitle] = []

    model_config = ConfigDict(extra="forbid")

    def get_title(self, lang: str = "en") -> Optional[str]:
        """if it can find a title in the specified language, it will return it"""
        for title in self.titles:
            if title.lang == lang:
                return title.title
        return None


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
    version: str = Field(alias="version")
    vector_string: str = Field(alias="vectorString")
    access_vector: str = Field(alias="accessVector")
    access_complexity: str = Field(alias="accessComplexity")
    authentication: str = Field(alias="authentication")
    confidentiality_impact: str = Field(alias="confidentialityImpact")
    integrity_impact: str = Field(alias="integrityImpact")
    availability_impact: str = Field(alias="availabilityImpact")
    base_score: float = Field(alias="baseScore")
    model_config = ConfigDict(extra="forbid")


class cvssMetricV2(BaseModel):
    source: str
    type: str
    cvss_data: CVSSV2Data = Field(alias="cvssData")
    base_severity: str = Field(alias="baseSeverity")
    exploitability_score: float = Field(alias="exploitabilityScore")
    impact_score: float = Field(alias="impactScore")
    ac_insuf_info: bool = Field(alias="acInsufInfo")
    obtain_all_privilege: bool = Field(alias="obtainAllPrivilege")
    obtain_user_privilege: bool = Field(alias="obtainUserPrivilege")
    obtain_other_privilege: bool = Field(alias="obtainOtherPrivilege")
    user_interaction_required: Optional[bool] = Field(
        None,
        alias="userInteractionRequired",
        serialization_alias="userInteractionRequired",
    )

    model_config = ConfigDict(extra="forbid")


class cvssMetricV3(BaseModel):
    source: Optional[str] = None
    type: Optional[str] = None
    exploitability_score: float = Field(alias="exploitabilityScore")
    impact_score: float = Field(alias="impactScore")
    cvss_data: Dict[str, Any] = Field(alias="cvssData")
    model_config = ConfigDict(extra="forbid")


class cvssMetricV4(BaseModel):
    source: str
    type: str
    cvss_data: Dict[str, Any] = Field(alias="cvssData")

    model_config = ConfigDict(extra="forbid")


class NVDMetrics(BaseModel):
    cvss_metric_v2: Optional[List[cvssMetricV2]] = Field(None, alias="cvssMetricV2")
    cvss_metric_v3: Optional[List[cvssMetricV3]] = Field(None, alias="cvssMetricV3")
    cvss_metric_v30: Optional[List[cvssMetricV3]] = Field(None, alias="cvssMetricV30")
    cvss_metric_v31: Optional[List[cvssMetricV3]] = Field(None, alias="cvssMetricV31")
    cvss_metric_v4: Optional[List[cvssMetricV4]] = Field(None, alias="cvssMetricV4")
    cvss_metric_v40: Optional[List[cvssMetricV4]] = Field(None, alias="cvssMetricV40")
    model_config = ConfigDict(extra="forbid")


class VendorComment(BaseModel):
    organization: str
    comment: str
    last_modified: Optional[datetime] = Field(None, alias="lastModified")

    model_config = ConfigDict(extra="forbid")


class CVETags(BaseModel):
    source_identifier: Optional[str] = Field(None, alias="sourceIdentifier")
    tags: List[str] = list()
    model_config = ConfigDict(extra="forbid")


class CPEMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vulnerable: bool
    criteria: str
    match_criteria_id: str = Field(alias="matchCriteriaId")
    version_start_including: Optional[str] = Field(None, alias="versionStartIncluding")
    version_start_excluding: Optional[str] = Field(None, alias="versionStartExcluding")
    version_end_including: Optional[str] = Field(None, alias="versionEndIncluding")
    version_end_excluding: Optional[str] = Field(None, alias="versionEndExcluding")


class Operator(StrEnum):
    AND = "AND"
    OR = "OR"


class NVDConfigurationNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operator: Operator
    negate: bool
    cpe_match: List[CPEMatch] = Field(list(), alias="cpeMatch")

    @field_validator("operator", mode="before")
    def validate_operator(cls, value: str) -> Operator:
        if value not in ["AND", "OR"]:
            raise ValueError("Operator must be one of AND, OR")
        return Operator(value)


class NVDConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operator: Optional[Operator] = None
    nodes: List[NVDConfigurationNode] = Field(list())


class NVDVulnerabilityData(BaseModel, WriteFileMixin):
    id: Optional[str] = None
    source_identifier: str = Field(alias="sourceIdentifier")
    published: datetime
    last_modified: datetime = Field(alias="lastModified")
    vuln_status: str = Field(alias="vulnStatus")
    cve_tags: List[CVETags] = Field(list(), alias="cveTags")
    descriptions: List[NVDDescription] = []
    references: List[NVDReference] = []
    weaknesses: List[NVDWeakness] = []
    configurations: List[NVDConfiguration] = Field(list())
    metrics: Optional[NVDMetrics] = None
    evaluator_comment: Optional[str] = Field(None, alias="evaluatorComment")
    evaluator_solution: Optional[str] = Field(None, alias="evaluatorSolution")
    evaluator_impact: Optional[str] = Field(None, alias="evaluatorImpact")
    vendor_comments: List[VendorComment] = Field(list(), alias="vendorComments")

    cisa_exploit_add: Optional[datetime] = Field(None, alias="cisaExploitAdd")
    cisa_action_due: Optional[datetime] = Field(None, alias="cisaActionDue")
    cisa_required_action: Optional[str] = Field(None, alias="cisaRequiredAction")
    cisa_vulnerability_name: Optional[str] = Field(None, alias="cisaVulnerabilityName")
    model_config = ConfigDict(extra="forbid")

    def get_description(self, lang: str) -> Optional[str]:
        """if it can find a description in the specified language, it will return it"""
        for desc in self.descriptions:
            if desc.lang == lang:
                return desc.value
        return None


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
        client_timeout: Optional[int] = None,
    ):
        if api_key is None:
            config = Config()  # type: ignore
        else:
            config = Config(api_key=api_key)
        self.api_key = config.api_key

        if client_session is not None:
            self.client = client_session
        else:
            if client_timeout is None:
                client_timeout = 60
            self.client = ClientSession(timeout=ClientTimeout(client_timeout))

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

        query: Dict[str, str] = {
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
            cpe_name_id: Optional[UUID4] = Field(None, alias="cpeNameId")
            cpe_match_string: Optional[str] = Field(None, alias="cpeMatchString")
            keyword_exact_match: Optional[bool] = Field(
                False,
                alias="keywordExactMatch",
                serialization_alias="keywordExactMatch",
            )
            match_criteria_id: Optional[UUID4] = Field(None, alias="matchCriteriaId")

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

        query: Dict[str, str] = {
            "resultsPerPage": str(results_per_page),
            "startIndex": str(start_index),
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

        query: Dict[str, str] = {
            "resultsPerPage": str(results_per_page),
            "startIndex": str(start_index),
        }
        if last_mod_start_date is not None:
            query["lastModStartDate"] = last_mod_start_date.isoformat()
        if last_mod_end_date is not None:
            query["lastModEndDate"] = last_mod_end_date.isoformat()
        if pub_start_date is not None:
            query["pubStartDate"] = pub_start_date.isoformat()
        if pub_end_date is not None:
            query["pubEndDate"] = pub_end_date.isoformat()
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

        attempts = 1
        while attempts <= 3:
            try:
                async with self.client.get(
                    CVE_API_URL, headers=headers, params=query
                ) as response:
                    response.raise_for_status()
                    text = await response.text()
                    try:
                        return NVDVulnerabilities.model_validate_json(text)
                    except Exception as error:
                        raise error
            except asyncio.TimeoutError:
                attempts += 1
                logger.error(f"Timeout, attempt {attempts}")
            except aiohttp.client_exceptions.ClientResponseError as error:
                if error.status == 503:
                    logger.error("Service unavailable (threw a 503), waiting 5 seconds")
                    await asyncio.sleep(5)
                else:
                    logger.error(f"Error: {error}, attempt {attempts}")
                attempts += 1
        raise asyncio.TimeoutError("Timeout error after 3 attempts")
