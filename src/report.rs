use chrono::{DateTime, Utc, TimeZone};
use serde::{Deserialize, Deserializer};
use std::net::IpAddr;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Feedback {
    pub report_metadata: ReportMetadata,
    pub policy_published: PolicyPublished,
    #[serde(rename = "record")]
    #[serde(default)]
    pub records: Vec<Record>
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct ReportMetadata {
    pub org_name: String,
    pub email: String,
    pub extra_contact_info: Option<String>,
    pub report_id: String,
    pub date_range: DateRange,
    #[serde(default)]
    pub errors: Vec<String>
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct PolicyPublished {
    pub domain: String,
    #[serde(rename = "adkim")]
    pub dkim_alignment: Alignment,
    #[serde(rename = "aspf")]
    pub spf_alignment: Alignment,
    #[serde(rename = "p")]
    pub domain_policy: Disposition,
    #[serde(rename = "sp")]
    pub subdomain_policy: Disposition,
    #[serde(rename = "pct")]
    pub percentage: u8,
    pub failure_reporting: Option<String>
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct DateRange {
    #[serde(deserialize_with = "deserialise_unix_timestamp")]
    pub begin: DateTime<Utc>,
    #[serde(deserialize_with = "deserialise_unix_timestamp")]
    pub end: DateTime<Utc>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum Disposition {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "quarantine")]
    Quarantine,
    #[serde(rename = "reject")]
    Reject
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum Alignment {
    #[serde(rename = "r")]
    Relaxed,
    #[serde(rename = "s")]
    Strict
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Record {
    pub row: Row,
    pub identifiers: Identifier,
    pub auth_results: AuthResults
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Identifier {
    pub envelope_to: Option<String>,
    pub envelope_from: Option<String>,
    pub header_from: String
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct AuthResults {
    #[serde(default)]
    pub spf: Vec<SpfAuthResult>,
    #[serde(default)]
    pub dkim: Vec<DkimAuthResult>
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct SpfAuthResult {
    pub domain: String,
    pub result: SpfResult
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum SpfResult {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "softfail")]
    SoftFail,
    #[serde(rename = "neutral")]
    Neutral,
    #[serde(rename = "temperror")]
    TempError,
    #[serde(rename = "permerror")]
    PermError
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct DkimAuthResult {
    pub domain: String,
    pub selector: String,
    pub result: DkimResult
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum DkimResult {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "fail")]
    Fail,
    #[serde(rename = "policy")]
    Policy,
    #[serde(rename = "neutral")]
    Neutral,
    #[serde(rename = "temperror")]
    #[serde(alias = "unknown")]
    TempError,
    #[serde(rename = "permerror")]
    #[serde(alias = "error")]
    PermError
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Row {
    pub source_ip: IpAddr,
    pub count: u64,
    pub policy_evaluated: PolicyEvaluated
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct PolicyEvaluated {
    pub disposition: Disposition,
    pub dkim: DmarcResult,
    pub spf: DmarcResult,
    #[serde(default)]
    pub reasons: Vec<PolicyOverrideReason>
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum DmarcResult {
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "fail")]
    Fail
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct PolicyOverrideReason {
    pub override_type: PolicyOverride,
    pub comment: Option<String>
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other
}

fn deserialise_unix_timestamp<'de, D>(
    deserializer: D,
) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let t: u64 = s.parse().unwrap();
    let s = format!("{}", t);
    Utc.datetime_from_str(&s, "%s").map_err(serde::de::Error::custom)
}
