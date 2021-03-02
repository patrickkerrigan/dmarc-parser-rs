use mailparse::{parse_mail, MailParseError, ParsedMail, MailHeaderMap};
use crate::report::Feedback;
use std::io::{Cursor, Read, Error};
use zip::result::ZipError;
use flate2::read::GzDecoder;
use regex::Regex;

pub mod report;

const MIME_ZIP: &'static str = "application/zip";
const MIME_X_ZIP: &'static str = "application/x-zip-compressed";
const MIME_GZIP: &'static str = "application/gzip";
const MIME_X_GZIP: &'static str = "application/x-gzip";
const MIME_XML: &'static str = "application/xml";
const MIME_TEXT_XML: &'static str = "text/xml";

const EXTENSION_ZIP: &'static str = "zip";
const EXTENSION_GZIP: &'static str = "gz";
const EXTENSION_XML: &'static str = "xml";

#[derive(Clone, Debug, Eq, PartialEq, Copy)]
enum ReportFormat {
    Zip,
    Gzip,
    Xml
}

impl ReportFormat {
    fn from_mimetype(s: &str) -> Option<Self> {
        match s {
            MIME_ZIP | MIME_X_ZIP => Some(Self::Zip),
            MIME_GZIP | MIME_X_GZIP => Some(Self::Gzip),
            MIME_XML | MIME_TEXT_XML => Some(Self::Xml),
            _ => None
        }
    }

    fn from_extension(s: &str) -> Option<Self> {
        match s {
            EXTENSION_ZIP => Some(Self::Zip),
            EXTENSION_GZIP => Some(Self::Gzip),
            EXTENSION_XML => Some(Self::Xml),
            _ => None
        }
    }
}

#[derive(Debug)]
struct AttachmentWithFormat<'a> {
    attachment: ParsedMail<'a>,
    format: Option<ReportFormat>
}

impl<'a> From<ParsedMail<'a>> for AttachmentWithFormat<'a> {
    fn from(email: ParsedMail<'a>) -> Self {
        AttachmentWithFormat {
            format: determine_format(&email),
            attachment: email
        }
    }
}

#[derive(Clone, Debug)]
pub struct ParseError(String);

pub fn parse_report_message(raw_message: &str) -> Result<Feedback, ParseError> {
    let mail = parse_mail(raw_message.as_bytes())?;

    let possible_attachments = if mail.subparts.is_empty() {
        vec![mail]
    } else {
        mail.subparts
    };

    let attachments: Vec<AttachmentWithFormat> = possible_attachments.into_iter()
        .map(|x| AttachmentWithFormat::from(x))
        .filter(|x| x.format.is_some())
        .collect();

    let attachment = attachments
        .first()
        .ok_or(ParseError("No suitable attachment found".into()))?;

    let xml = match attachment {
        AttachmentWithFormat {format: Some(ReportFormat::Zip), attachment} => decode_zip(attachment)?,
        AttachmentWithFormat {format: Some(ReportFormat::Gzip), attachment} => decode_gzip(attachment)?,
        AttachmentWithFormat {format: Some(ReportFormat::Xml), attachment} => decode_xml(attachment)?,

        _ => return Err(ParseError("No suitable attachment found".into()))
    };

    Ok(serde_xml_rs::from_str(&xml)?)
}

fn decode_zip(attachment: &ParsedMail) -> Result<String, ParseError> {
    let cursor = Cursor::new(attachment.get_body_raw()?);
    let mut zip = zip::ZipArchive::new(cursor)?;

    let mut report_string = String::new();
    zip.by_index(0)?.read_to_string(&mut report_string)?;

    Ok(report_string)
}

fn decode_gzip(attachment: &ParsedMail) -> Result<String, ParseError> {
    let cursor = Cursor::new(attachment.get_body_raw()?);
    let mut zip = GzDecoder::new(cursor);

    let mut report_string = String::new();
    zip.read_to_string(&mut report_string)?;

    Ok(report_string)
}

fn decode_xml(attachment: &ParsedMail) -> Result<String, ParseError> {
    String::from_utf8(attachment.get_body_raw()?)
        .map_err(|_| ParseError("Invalid UTF-8 document".into()))
}

fn determine_format(email: &ParsedMail) -> Option<ReportFormat> {
    ReportFormat::from_mimetype(email.ctype.mimetype.as_str())
        .map_or_else(|| guess_format_from_name(email), |x| Some(x))

}

fn guess_format_from_name(email: &ParsedMail) -> Option<ReportFormat> {
    let disposition: String = email.headers.get_first_value("Content-Disposition")?;

    let filename_regex = Regex::new(r#"filename=(?:["']?)(?P<filename>[^\s"']+)(?:['"]?)"#).unwrap();
    let matches = filename_regex.captures(&disposition)?;
    let filename = matches.name("filename")?.as_str();

    let mut x = filename.rsplitn(2, ".");

    ReportFormat::from_extension(x.next()?)
}

impl From<MailParseError> for ParseError {
    fn from(e: MailParseError) -> Self {
        ParseError(format!("{}", e))
    }
}

impl From<ZipError> for ParseError {
    fn from(e: ZipError) -> Self {
        ParseError(format!("{:?}", e))
    }
}

impl From<std::io::Error> for ParseError {
    fn from(e: Error) -> Self {
        ParseError(format!("{}", e))
    }
}

impl From<serde_xml_rs::Error> for ParseError {
    fn from(e: serde_xml_rs::Error) -> Self {
        ParseError(format!("{:?}", e))
    }
}
