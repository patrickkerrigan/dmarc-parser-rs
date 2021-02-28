use std::fs::File;
use std::io::Read;
use dmarc_parser::{parse_report_message};
use dmarc_parser::report::{Feedback, ReportMetadata, DateRange, PolicyPublished, Alignment, Disposition, Record, Row, PolicyEvaluated, DmarcResult, Identifier, AuthResults, SpfAuthResult, SpfResult, DkimAuthResult, DkimResult};
use chrono::{Utc, TimeZone};

#[test]
fn test_zip_decode() {
    let mut input = String::new();
    let _ = File::open("tests/resources/test.zip.eml").unwrap().read_to_string(&mut input);

    let x = parse_report_message(&input).unwrap();

    assert_eq!(get_expected_feedback(), x);
}

#[test]
fn test_gzip_decode() {
    let mut input = String::new();
    let _ = File::open("tests/resources/test.gz.eml").unwrap().read_to_string(&mut input);

    let x = parse_report_message(&input).unwrap();

    assert_eq!(get_expected_feedback(), x);
}


fn get_expected_feedback() -> Feedback {
    Feedback {
        report_metadata: ReportMetadata {
            org_name: "Test org".into(),
            email: "noreply@example.com".into(),
            extra_contact_info: Some(
                "https://example.org/dmarc".into(),
            ),
            report_id: "123456".into(),
            date_range: DateRange {
                begin: Utc.datetime_from_str("2017-04-10T00:00:00Z", "%+").unwrap(),
                end: Utc.datetime_from_str("2017-04-10T23:59:59Z", "%+").unwrap()
            },
            errors: vec![],
        },
        policy_published: PolicyPublished {
            domain: "patrickkerrigan.uk".into(),
            dkim_alignment: Alignment::Strict,
            spf_alignment: Alignment::Relaxed,
            domain_policy: Disposition::Reject,
            subdomain_policy: Some(Disposition::None),
            percentage: 100,
            failure_reporting: None,
        },
        records: vec![
            Record {
                row: Row {
                    source_ip: "192.168.1.43".parse().unwrap(),
                    count: 8,
                    policy_evaluated: PolicyEvaluated {
                        disposition: Disposition::Reject,
                        dkim: DmarcResult::Fail,
                        spf: DmarcResult::Fail,
                        reasons: vec![],
                    },
                },
                identifiers: Identifier {
                    envelope_to: None,
                    envelope_from: None,
                    header_from: "patrickkerrigan.uk".into(),
                },
                auth_results: AuthResults {
                    spf: vec![
                        SpfAuthResult {
                            domain: "patrickkerrigan.uk".into(),
                            result: SpfResult::Fail,
                        },
                    ],
                    dkim: vec![],
                },
            },
            Record {
                row: Row {
                    source_ip: "192.168.34.78".parse().unwrap(),
                    count: 1,
                    policy_evaluated: PolicyEvaluated {
                        disposition: Disposition::None,
                        dkim: DmarcResult::Pass,
                        spf: DmarcResult::Pass,
                        reasons: vec![],
                    },
                },
                identifiers: Identifier {
                    envelope_to: None,
                    envelope_from: None,
                    header_from: "patrickkerrigan.uk".into(),
                },
                auth_results: AuthResults {
                    spf: vec![
                        SpfAuthResult {
                            domain: "patrickkerrigan.uk".into(),
                            result: SpfResult::Pass,
                        },
                    ],
                    dkim: vec![
                        DkimAuthResult {
                            domain: "patrickkerrigan.uk".into(),
                            selector: "mail".into(),
                            result: DkimResult::Pass,
                        },
                    ],
                },
            },
            Record {
                row: Row {
                    source_ip: "192.168.23.53".parse().unwrap(),
                    count: 1,
                    policy_evaluated: PolicyEvaluated {
                        disposition: Disposition::None,
                        dkim: DmarcResult::Pass,
                        spf: DmarcResult::Pass,
                        reasons: vec![],
                    },
                },
                identifiers: Identifier {
                    envelope_to: None,
                    envelope_from: None,
                    header_from: "patrickkerrigan.uk".into(),
                },
                auth_results: AuthResults {
                    spf: vec![
                        SpfAuthResult {
                            domain: "patrickkerrigan.uk".into(),
                            result: SpfResult::Pass,
                        },
                    ],
                    dkim: vec![
                        DkimAuthResult {
                            domain: "patrickkerrigan.uk".into(),
                            selector: "mail".into(),
                            result: DkimResult::Pass,
                        },
                    ],
                },
            },
        ],
    }
}
