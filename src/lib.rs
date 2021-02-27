use mailparse::{parse_mail, MailParseError, ParsedMail};
use crate::report::Feedback;
use std::io::{Cursor, Read, Error};
use zip::result::ZipError;
use flate2::read::GzDecoder;

pub mod report;

const MIME_ZIP: &'static str = "application/zip";
const MIME_X_ZIP: &'static str = "application/x-zip-compressed";
const MIME_GZIP: &'static str = "application/gzip";
const MIME_X_GZIP: &'static str = "application/x-gzip";

#[derive(Clone, Debug)]
pub struct ParseError(String);

pub fn parse_report_message(raw_message: &str) -> Result<Feedback, ParseError> {
    let mail = parse_mail(raw_message.as_bytes())?;

    let subparts: Vec<ParsedMail> = mail.subparts.into_iter()
        .filter(|x| {
            [
                MIME_ZIP,
                MIME_X_ZIP,
                MIME_GZIP,
                MIME_X_GZIP
            ].contains(&x.ctype.mimetype.as_str())
        })
        .collect();

    let attachment = subparts
        .first()
        .ok_or(ParseError("No suitable attachment found".into()))?;

    let xml = match attachment.ctype.mimetype.as_str() {
        MIME_ZIP | MIME_X_ZIP => decode_zip(attachment)?,

        MIME_GZIP | MIME_X_GZIP => decode_gzip(attachment)?,

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
