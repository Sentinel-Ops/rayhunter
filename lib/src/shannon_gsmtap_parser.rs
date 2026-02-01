//! Samsung Shannon DM message to GSMTAP conversion
//!
//! This module converts Samsung Shannon diagnostic messages to GSMTAP format,
//! allowing reuse of existing analysis heuristics.
//!
//! Note: The exact format of Samsung DM messages requires reverse engineering
//! from real device captures. This implementation provides the framework
//! and will be refined as more data becomes available.

use crate::gsmtap::*;
use crate::shannon::{DmLogCategory, DmMessage, DmMessageType};

use chrono::{DateTime, FixedOffset};
use log::{debug, warn};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShannonParserError {
    #[error("Unknown message category: {0:#x}")]
    UnknownCategory(u16),
    #[error("Failed to parse LTE RRC message: {0}")]
    LteRrcParseError(String),
    #[error("Failed to parse NAS message: {0}")]
    NasParseError(String),
    #[error("Message payload too short: need {need} bytes, got {got}")]
    PayloadTooShort { need: usize, got: usize },
    #[error("Unsupported message type: {0:?}")]
    UnsupportedMessageType(DmMessageType),
}

/// Timestamp for Shannon messages
#[derive(Debug, Clone, Copy)]
pub struct ShannonTimestamp {
    pub raw: u64,
}

impl ShannonTimestamp {
    pub fn new(raw: u64) -> Self {
        Self { raw }
    }

    /// Convert to chrono DateTime
    /// Note: Samsung timestamp format needs to be determined from real captures
    pub fn to_datetime(&self) -> DateTime<FixedOffset> {
        // Placeholder: assuming milliseconds since Unix epoch
        // This needs to be verified with real device captures
        let epoch = DateTime::parse_from_rfc3339("1970-01-01T00:00:00+00:00").unwrap();
        let delta = chrono::Duration::milliseconds(self.raw as i64);
        epoch + delta
    }
}

/// Parse a Samsung DM message into GSMTAP format
pub fn parse(
    msg: &DmMessage,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    // Only process Log messages
    if !matches!(msg.msg_type, DmMessageType::Log) {
        debug!("Skipping non-log message type: {:?}", msg.msg_type);
        return Ok(None);
    }

    let timestamp = ShannonTimestamp::new(msg.timestamp);

    match msg.category {
        // LTE RRC messages
        cat if cat >= DmLogCategory::LteRrc as u16 && cat < DmLogCategory::LteNas as u16 => {
            parse_lte_rrc_message(&msg.payload, timestamp)
        }
        // LTE NAS messages
        cat if cat >= DmLogCategory::LteNas as u16 && cat < DmLogCategory::NrRrc as u16 => {
            parse_lte_nas_message(&msg.payload, timestamp)
        }
        // 5G NR RRC messages
        cat if cat >= DmLogCategory::NrRrc as u16 && cat < DmLogCategory::NrNas as u16 => {
            parse_nr_rrc_message(&msg.payload, timestamp)
        }
        // 5G NR NAS messages
        cat if cat >= DmLogCategory::NrNas as u16 && cat < DmLogCategory::IpTraffic as u16 => {
            parse_nr_nas_message(&msg.payload, timestamp)
        }
        // GSM/GPRS messages
        cat if cat >= DmLogCategory::GsmL2 as u16 && cat < DmLogCategory::GsmL3 as u16 => {
            parse_gsm_l2_message(&msg.payload, timestamp)
        }
        cat if cat >= DmLogCategory::GsmL3 as u16 && cat < DmLogCategory::Wcdma as u16 => {
            parse_gsm_l3_message(&msg.payload, timestamp)
        }
        // WCDMA/UMTS messages
        cat if cat >= DmLogCategory::Wcdma as u16 && cat < DmLogCategory::LteRrc as u16 => {
            parse_wcdma_message(&msg.payload, timestamp)
        }
        _ => {
            debug!("Unknown message category: {:#x}", msg.category);
            Ok(None)
        }
    }
}

/// Parse LTE RRC OTA message from Samsung DM payload
fn parse_lte_rrc_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    // Samsung LTE RRC message format (to be refined with real captures):
    // Offset 0: Channel type / PDU number
    // Offset 1-2: ARFCN (EARFCN)
    // Offset 3-4: Physical Cell ID
    // Offset 5-6: SFN/SubFN
    // Offset 7+: RRC message payload

    if payload.len() < 8 {
        return Err(ShannonParserError::PayloadTooShort {
            need: 8,
            got: payload.len(),
        });
    }

    let pdu_num = payload[0];
    let earfcn = u16::from_le_bytes([payload[1], payload[2]]);
    let _pci = u16::from_le_bytes([payload[3], payload[4]]);
    let sfn_subfn = u16::from_le_bytes([payload[5], payload[6]]);
    let rrc_payload = &payload[7..];

    // Map PDU number to GSMTAP LTE RRC subtype
    // Note: These mappings need verification with real Samsung captures
    let gsmtap_type = match pdu_num {
        1 => GsmtapType::LteRrc(LteRrcSubtype::BcchBch),
        2 => GsmtapType::LteRrc(LteRrcSubtype::BcchDlSch),
        3 => GsmtapType::LteRrc(LteRrcSubtype::MCCH),
        4 => GsmtapType::LteRrc(LteRrcSubtype::PCCH),
        5 => GsmtapType::LteRrc(LteRrcSubtype::DlCcch),
        6 => GsmtapType::LteRrc(LteRrcSubtype::DlDcch),
        7 => GsmtapType::LteRrc(LteRrcSubtype::UlCcch),
        8 => GsmtapType::LteRrc(LteRrcSubtype::UlDcch),
        _ => {
            warn!("Unknown LTE RRC PDU number: {}", pdu_num);
            GsmtapType::LteRrc(LteRrcSubtype::DlDcch) // Default fallback
        }
    };

    let mut header = GsmtapHeader::new(gsmtap_type);
    header.arfcn = earfcn;
    header.frame_number = (sfn_subfn >> 4) as u32;
    header.subslot = (sfn_subfn & 0xf) as u8;

    Ok(Some((
        timestamp,
        GsmtapMessage {
            header,
            payload: rrc_payload.to_vec(),
        },
    )))
}

/// Parse LTE NAS message from Samsung DM payload
fn parse_lte_nas_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    // Samsung LTE NAS message format (to be refined):
    // Offset 0: Direction (0=downlink, 1=uplink)
    // Offset 1+: NAS message payload

    if payload.is_empty() {
        return Err(ShannonParserError::PayloadTooShort { need: 1, got: 0 });
    }

    let direction = payload[0];
    let nas_payload = if payload.len() > 1 {
        &payload[1..]
    } else {
        &[]
    };

    let mut header = GsmtapHeader::new(GsmtapType::LteNas(LteNasSubtype::Plain));
    header.uplink = direction != 0;

    Ok(Some((
        timestamp,
        GsmtapMessage {
            header,
            payload: nas_payload.to_vec(),
        },
    )))
}

/// Parse 5G NR RRC message from Samsung DM payload
fn parse_nr_rrc_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    // 5G NR RRC parsing - similar structure to LTE RRC
    // Format to be determined from real captures

    if payload.len() < 4 {
        return Err(ShannonParserError::PayloadTooShort {
            need: 4,
            got: payload.len(),
        });
    }

    // Placeholder: treat as generic NR RRC
    let header = GsmtapHeader::new(GsmtapType::LteRrc(LteRrcSubtype::DlDcch));

    Ok(Some((
        timestamp,
        GsmtapMessage {
            header,
            payload: payload.to_vec(),
        },
    )))
}

/// Parse 5G NR NAS message from Samsung DM payload
fn parse_nr_nas_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    // Similar to LTE NAS
    parse_lte_nas_message(payload, timestamp)
}

/// Parse GSM Layer 2 message
fn parse_gsm_l2_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    if payload.is_empty() {
        return Ok(None);
    }

    // GSM L2 (MAC) signaling
    let header = GsmtapHeader::new(GsmtapType::Um(UmSubtype::Sdcch));

    Ok(Some((
        timestamp,
        GsmtapMessage {
            header,
            payload: payload.to_vec(),
        },
    )))
}

/// Parse GSM Layer 3 message
fn parse_gsm_l3_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    if payload.is_empty() {
        return Ok(None);
    }

    // GSM RR signaling
    let header = GsmtapHeader::new(GsmtapType::Um(UmSubtype::Bcch));

    Ok(Some((
        timestamp,
        GsmtapMessage {
            header,
            payload: payload.to_vec(),
        },
    )))
}

/// Parse WCDMA/UMTS message
fn parse_wcdma_message(
    payload: &[u8],
    timestamp: ShannonTimestamp,
) -> Result<Option<(ShannonTimestamp, GsmtapMessage)>, ShannonParserError> {
    if payload.is_empty() {
        return Ok(None);
    }

    // WCDMA RRC signaling - using ABIS as placeholder type
    let header = GsmtapHeader::new(GsmtapType::Abis);

    Ok(Some((
        timestamp,
        GsmtapMessage {
            header,
            payload: payload.to_vec(),
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shannon::SipcRawHeader;

    fn make_test_message(category: u16, payload: Vec<u8>) -> DmMessage {
        DmMessage {
            header: SipcRawHeader {
                channel: 28,
                control: 0,
                len: payload.len() as u16,
            },
            msg_type: DmMessageType::Log,
            category,
            timestamp: 1234567890,
            payload,
        }
    }

    #[test]
    fn test_parse_lte_rrc_message() {
        // Create a test LTE RRC message with minimal header
        let payload = vec![
            5, // PDU num (DlCcch)
            0x00, 0x01, // EARFCN
            0x10, 0x00, // PCI
            0x12, 0x34, // SFN/SubFN
            0xAA, 0xBB, 0xCC, // RRC payload
        ];
        let msg = make_test_message(DmLogCategory::LteRrc as u16, payload);

        let result = parse(&msg).unwrap();
        assert!(result.is_some());

        let (_, gsmtap) = result.unwrap();
        assert!(matches!(
            gsmtap.header.gsmtap_type,
            GsmtapType::LteRrc(LteRrcSubtype::DlCcch)
        ));
        assert_eq!(gsmtap.payload, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_parse_lte_nas_message() {
        let payload = vec![
            0, // Direction (downlink)
            0x07, 0x41, 0x02, // NAS payload (example)
        ];
        let msg = make_test_message(DmLogCategory::LteNas as u16, payload);

        let result = parse(&msg).unwrap();
        assert!(result.is_some());

        let (_, gsmtap) = result.unwrap();
        assert!(matches!(
            gsmtap.header.gsmtap_type,
            GsmtapType::LteNas(LteNasSubtype::Plain)
        ));
        assert!(!gsmtap.header.uplink);
    }

    #[test]
    fn test_skip_non_log_message() {
        let msg = DmMessage {
            header: SipcRawHeader {
                channel: 28,
                control: 0,
                len: 10,
            },
            msg_type: DmMessageType::Response,
            category: DmLogCategory::LteRrc as u16,
            timestamp: 0,
            payload: vec![0; 10],
        };

        let result = parse(&msg).unwrap();
        assert!(result.is_none());
    }
}
