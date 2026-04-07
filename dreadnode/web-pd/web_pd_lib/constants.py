PD_BINARY_NAMES = (
    "subfinder",
    "httpx",
    "katana",
    "dnsx",
    "naabu",
    "tlsx",
    "alterx",
    "nuclei",
)

ATTR_SCAN_ID = "dreadnode.pd.scan_id"
ATTR_EVENT_KIND = "dreadnode.pd.event_kind"
ATTR_TARGET = "dreadnode.pd.target"
ATTR_TOOL = "dreadnode.pd.tool"
ATTR_JOB_ID = "dreadnode.pd.job_id"
ATTR_DEDUPE_KEY = "dreadnode.pd.dedupe_key"
ATTR_OPPORTUNITY_KEY = "dreadnode.pd.opportunity_key"
ATTR_OPPORTUNITY_KIND = "dreadnode.pd.opportunity_kind"
ATTR_PRIORITY = "dreadnode.pd.priority"
ATTR_STATUS = "dreadnode.pd.status"
ATTR_OWNER = "dreadnode.pd.owner"
ATTR_SOURCE = "dreadnode.pd.source"
ATTR_SEARCH_TEXT = "dreadnode.pd.search_text"
ATTR_SUMMARY = "dreadnode.pd.summary"
ATTR_ARTIFACT_PATH = "dreadnode.pd.artifact_path"
ATTR_PAYLOAD = "dreadnode.pd.payload"

EVENT_SCAN_STARTED = "pd.scan.started"
EVENT_SCAN_SUMMARY = "pd.scan.summary"
EVENT_JOB_REQUESTED = "pd.job.requested"
EVENT_JOB_STARTED = "pd.job.started"
EVENT_JOB_COMPLETED = "pd.job.completed"
EVENT_FACT_SUBDOMAIN = "pd.fact.subdomain"
EVENT_FACT_SERVICE = "pd.fact.service"
EVENT_FACT_URL = "pd.fact.url"
EVENT_FACT_DNS = "pd.fact.dns"
EVENT_FACT_PORT = "pd.fact.port"
EVENT_FACT_CERTIFICATE = "pd.fact.certificate"
EVENT_FACT_FINDING = "pd.fact.finding"
EVENT_OPPORTUNITY_INTERESTING_SERVICE = "pd.opportunity.interesting_service"
EVENT_OPPORTUNITY_INTERESTING_URL = "pd.opportunity.interesting_url"
EVENT_OPPORTUNITY_VALIDATION_CANDIDATE = "pd.opportunity.validation_candidate"
EVENT_OPPORTUNITY_CLAIMED = "pd.opportunity.claimed"
EVENT_OPPORTUNITY_COMPLETED = "pd.opportunity.completed"

FACT_EVENTS = {
    EVENT_FACT_SUBDOMAIN,
    EVENT_FACT_SERVICE,
    EVENT_FACT_URL,
    EVENT_FACT_DNS,
    EVENT_FACT_PORT,
    EVENT_FACT_CERTIFICATE,
    EVENT_FACT_FINDING,
}

OPPORTUNITY_EVENTS = {
    EVENT_OPPORTUNITY_INTERESTING_SERVICE,
    EVENT_OPPORTUNITY_INTERESTING_URL,
    EVENT_OPPORTUNITY_VALIDATION_CANDIDATE,
    EVENT_OPPORTUNITY_CLAIMED,
    EVENT_OPPORTUNITY_COMPLETED,
}

EVENT_TO_KIND = {
    EVENT_SCAN_STARTED: "scan.started",
    EVENT_SCAN_SUMMARY: "scan.summary",
    EVENT_JOB_REQUESTED: "job.requested",
    EVENT_JOB_STARTED: "job.started",
    EVENT_JOB_COMPLETED: "job.completed",
    EVENT_FACT_SUBDOMAIN: "fact.subdomain",
    EVENT_FACT_SERVICE: "fact.service",
    EVENT_FACT_URL: "fact.url",
    EVENT_FACT_DNS: "fact.dns",
    EVENT_FACT_PORT: "fact.port",
    EVENT_FACT_CERTIFICATE: "fact.certificate",
    EVENT_FACT_FINDING: "fact.finding",
    EVENT_OPPORTUNITY_INTERESTING_SERVICE: "opportunity.interesting_service",
    EVENT_OPPORTUNITY_INTERESTING_URL: "opportunity.interesting_url",
    EVENT_OPPORTUNITY_VALIDATION_CANDIDATE: "opportunity.validation_candidate",
    EVENT_OPPORTUNITY_CLAIMED: "opportunity.claimed",
    EVENT_OPPORTUNITY_COMPLETED: "opportunity.completed",
}

OPEN_OPPORTUNITY_STATUSES = {"open", "claimed"}
