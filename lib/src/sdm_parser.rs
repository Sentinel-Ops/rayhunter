//! Samsung SDM (Silent Diagnostic Monitor) file format parser
//!
//! This module parses the native `.sdm` files produced by Samsung Shannon modems
//! found in `/data/vendor/slog/` on Pixel 6+ devices.
//!
//! File format (reverse-engineered from real Pixel 9 captures):
//!
//! ## Header Structure (first ~0x140 bytes)
//! - Offset 0x00: Record length (2 bytes LE)
//! - Offset 0x02: Magic/type (4 bytes): 0x0004fd39
//! - Offset 0x0a: "Pixel Logger Ver. 1 Jun. 10,2021" (null-terminated)
//! - Offset 0x38: Timezone string e.g. "Etc/GMT" (null-terminated)
//! - Offset 0x80+: Extended info with IMEI, modem version (semicolon-separated)
//!
//! ## Message Structure
//! Messages are variable-length records with the following format:
//! - Type: 2 bytes LE (0x0b00=LTE RRC, 0x0c00=LTE NAS, 0x0d00=NR, 0x0e00=GSM, 0x0f00=Debug)
//! - Subtype: 2 bytes LE
//! - Timestamp: 4 bytes (format TBD, contains "fD"/"gD" patterns = 0x4466/0x4467)
//! - Flags/Length: 4 bytes
//! - Payload: variable length
//!
//! Note: The exact message boundaries are determined by length fields, not 0x7f markers.

use std::io::{Read, Seek, SeekFrom};

use log;
use thiserror::Error;

/// SDM message type categories (first byte of 2-byte type field)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SdmMessageCategory {
    /// LTE RRC signaling (0x0b)
    LteRrc = 0x0b,
    /// LTE NAS signaling (0x0c)
    LteNas = 0x0c,
    /// 5G NR signaling (0x0d)
    Nr = 0x0d,
    /// GSM/GPRS signaling (0x0e)
    Gsm = 0x0e,
    /// Debug/text log messages (0x0f)
    Debug = 0x0f,
    /// Unknown category
    Unknown = 0xff,
}

impl From<u8> for SdmMessageCategory {
    fn from(val: u8) -> Self {
        match val {
            0x0b => SdmMessageCategory::LteRrc,
            0x0c => SdmMessageCategory::LteNas,
            0x0d => SdmMessageCategory::Nr,
            0x0e => SdmMessageCategory::Gsm,
            0x0f => SdmMessageCategory::Debug,
            _ => SdmMessageCategory::Unknown,
        }
    }
}

#[derive(Debug, Error)]
pub enum SdmParseError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Invalid SDM header: {0}")]
    InvalidHeader(String),
    #[error("Unexpected end of file")]
    UnexpectedEof,
    #[error("Invalid message format at offset {0}: {1}")]
    InvalidMessage(u64, String),
    #[error("Message length exceeds maximum at offset {0}")]
    MessageTooLarge(u64),
}

/// SDM file header information
#[derive(Debug, Clone)]
pub struct SdmHeader {
    /// Logger version string (e.g., "Pixel Logger Ver. 1 Jun. 10,2021")
    pub logger_version: String,
    /// Timezone string (e.g., "Etc/GMT")
    pub timezone: String,
    /// Library version if present
    pub lib_version: Option<String>,
    /// Modem firmware version (e.g., "g5400c-250908-251105-B-14386369")
    pub modem_version: Option<String>,
    /// Device IMEI (15 digits)
    pub imei: Option<String>,
    /// Header magic value for format verification
    pub magic: u32,
    /// Total header size in bytes
    pub header_size: u64,
}

/// A single message from an SDM file
#[derive(Debug, Clone)]
pub struct SdmMessage {
    /// File offset where this message starts
    pub offset: u64,
    /// Raw timestamp value (format varies by message type)
    pub timestamp: u64,
    /// Message type (high byte of category)
    pub msg_type: u8,
    /// Full category value (type + subtype)
    pub category: u16,
    /// Message subtype (low byte of category)
    pub subtype: u8,
    /// Raw payload data
    pub payload: Vec<u8>,
}

/// SDM header magic value
pub const SDM_HEADER_MAGIC: u32 = 0x0004fd39;

impl SdmMessage {
    /// Get the message category enum
    pub fn get_category(&self) -> SdmMessageCategory {
        SdmMessageCategory::from(self.msg_type)
    }

    /// Check if this is an LTE RRC message
    pub fn is_lte_rrc(&self) -> bool {
        self.msg_type == SdmMessageCategory::LteRrc as u8
    }

    /// Check if this is an LTE NAS message
    pub fn is_lte_nas(&self) -> bool {
        self.msg_type == SdmMessageCategory::LteNas as u8
    }

    /// Check if this is a NAS message (LTE or NR)
    pub fn is_nas(&self) -> bool {
        self.is_lte_nas() || self.is_nr_nas()
    }

    /// Check if this is a 5G NR message
    pub fn is_nr(&self) -> bool {
        self.msg_type == SdmMessageCategory::Nr as u8
    }

    /// Check if this is a 5G NR NAS message (subtype check)
    pub fn is_nr_nas(&self) -> bool {
        // NR NAS messages have specific subtypes within the NR category
        self.is_nr() && (self.subtype >= 0x10 && self.subtype < 0x20)
    }

    /// Check if this is a GSM message
    pub fn is_gsm(&self) -> bool {
        self.msg_type == SdmMessageCategory::Gsm as u8
    }

    /// Check if this is a debug/text log message
    pub fn is_debug_log(&self) -> bool {
        if self.msg_type == SdmMessageCategory::Debug as u8 {
            return true;
        }
        // Also check if payload contains mostly printable ASCII
        if self.payload.is_empty() {
            return false;
        }
        let printable_count = self.payload
            .iter()
            .filter(|&&b| b >= 0x20 && b < 0x7f)
            .count();
        printable_count > self.payload.len() / 2
    }

    /// Try to extract text content from debug messages
    pub fn as_text(&self) -> Option<String> {
        if self.is_debug_log() {
            // Try to find null terminator and extract clean string
            let end = self.payload.iter().position(|&b| b == 0).unwrap_or(self.payload.len());
            String::from_utf8(self.payload[..end].to_vec()).ok()
        } else {
            None
        }
    }

    /// Check if this message contains signaling data (RRC, NAS, etc.)
    pub fn is_signaling(&self) -> bool {
        self.is_lte_rrc() || self.is_nas() || self.is_nr() || self.is_gsm()
    }
}

/// SDM file parser
pub struct SdmParser<R: Read + Seek> {
    reader: R,
    header: Option<SdmHeader>,
    current_offset: u64,
    file_size: u64,
}

impl<R: Read + Seek> SdmParser<R> {
    pub fn new(mut reader: R) -> Self {
        // Get file size
        let file_size = reader.seek(SeekFrom::End(0)).unwrap_or(0);
        let _ = reader.seek(SeekFrom::Start(0));

        Self {
            reader,
            header: None,
            current_offset: 0,
            file_size,
        }
    }

    /// Get the parsed header, if available
    pub fn header(&self) -> Option<&SdmHeader> {
        self.header.as_ref()
    }

    /// Parse the file header
    pub fn parse_header(&mut self) -> Result<SdmHeader, SdmParseError> {
        self.reader.seek(SeekFrom::Start(0))?;

        // Read initial header bytes
        let mut buf = [0u8; 6];
        self.reader.read_exact(&mut buf)?;

        // Parse initial record: length (2 bytes) + magic (4 bytes)
        let _record_len = u16::from_le_bytes([buf[0], buf[1]]);
        let magic = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]);

        // Verify magic (0x0004fd39 for SDM format)
        if magic != SDM_HEADER_MAGIC && magic != 0x0004fd39 {
            // Try alternative: might be a different offset or format variant
            log::debug!("SDM magic mismatch: got {:#x}, expected {:#x}", magic, SDM_HEADER_MAGIC);
        }

        // Read logger version string area (starts around offset 0x0a)
        self.reader.seek(SeekFrom::Start(0x0a))?;
        let mut version_buf = [0u8; 48];
        self.reader.read_exact(&mut version_buf)?;

        let version_str = String::from_utf8_lossy(&version_buf);
        let logger_version = if let Some(start) = version_str.find("Pixel Logger") {
            let end = version_str[start..].find('\0').unwrap_or(32);
            version_str[start..start + end].trim().to_string()
        } else if let Some(start) = version_str.find("Logger") {
            let end = version_str[start..].find('\0').unwrap_or(32);
            version_str[start..start + end].trim().to_string()
        } else {
            "Unknown".to_string()
        };

        // Find timezone (around offset 0x38)
        self.reader.seek(SeekFrom::Start(0x38))?;
        let mut tz_buf = [0u8; 16];
        self.reader.read_exact(&mut tz_buf)?;
        let tz_str = String::from_utf8_lossy(&tz_buf);
        let timezone = tz_str.split('\0').next().unwrap_or("UTC").trim().to_string();

        // Read extended header for IMEI and modem version (offset 0x80+)
        self.reader.seek(SeekFrom::Start(0x80))?;
        let mut ext_buf = [0u8; 512];
        let bytes_read = self.reader.read(&mut ext_buf)?;
        let ext_str = String::from_utf8_lossy(&ext_buf[..bytes_read]);

        // Extract modem version (g5400c-..., g5123b-..., etc.)
        let modem_version = ext_str
            .split(|c| c == ';' || c == '\0' || c == '\n')
            .find(|s| {
                let s = s.trim();
                s.starts_with("g5") || s.starts_with("G5") || s.contains("Modem")
            })
            .map(|s| s.trim().to_string());

        // Extract IMEI (15 digit number)
        let imei = ext_str
            .split(|c| c == ';' || c == '\0' || c == '\n')
            .find(|s| {
                let s = s.trim();
                s.len() == 15 && s.chars().all(|c| c.is_ascii_digit())
            })
            .map(|s| s.trim().to_string());

        // Determine where messages start (scan for first message pattern)
        let header_size = self.find_message_start()?;

        let header = SdmHeader {
            logger_version,
            timezone,
            lib_version: None,
            modem_version,
            imei,
            magic,
            header_size,
        };

        self.header = Some(header.clone());
        self.current_offset = header_size;

        Ok(header)
    }

    /// Scan for the start of the message area
    fn find_message_start(&mut self) -> Result<u64, SdmParseError> {
        // Messages typically start after the header area
        // Look for patterns that indicate message start

        // Default header size based on real captures
        let default_header_size = 0x140u64;

        // Try to find message marker patterns
        self.reader.seek(SeekFrom::Start(0x100))?;
        let mut scan_buf = [0u8; 256];
        if self.reader.read(&mut scan_buf).is_ok() {
            // Look for message type patterns (0x0b, 0x0c, 0x0d, 0x0e, 0x0f followed by 0x00)
            for i in 0..scan_buf.len().saturating_sub(2) {
                if (scan_buf[i] >= 0x0b && scan_buf[i] <= 0x0f) && scan_buf[i + 1] == 0x00 {
                    // Found potential message start
                    let offset = 0x100 + i as u64;
                    // Verify by checking if it looks like a valid message
                    if self.verify_message_at(offset).is_ok() {
                        return Ok(offset);
                    }
                }
            }
        }

        Ok(default_header_size)
    }

    /// Verify that there's a valid message at the given offset
    fn verify_message_at(&mut self, offset: u64) -> Result<(), SdmParseError> {
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;

        // Check for valid message type
        let msg_type = buf[0];
        if msg_type >= 0x0b && msg_type <= 0x0f {
            Ok(())
        } else {
            Err(SdmParseError::InvalidMessage(offset, "Invalid message type".to_string()))
        }
    }

    /// Read the next message from the file
    pub fn next_message(&mut self) -> Result<Option<SdmMessage>, SdmParseError> {
        if self.header.is_none() {
            self.parse_header()?;
        }

        // Check if we've reached end of file
        if self.current_offset >= self.file_size {
            return Ok(None);
        }

        self.reader.seek(SeekFrom::Start(self.current_offset))?;

        // Try two parsing strategies:
        // 1. Length-prefixed messages (newer format)
        // 2. Type-first messages (alternative format)

        let message_offset = self.current_offset;

        // Read initial bytes to determine format
        let mut header_buf = [0u8; 16];
        match self.reader.read(&mut header_buf) {
            Ok(n) if n < 4 => return Ok(None),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(SdmParseError::IoError(e)),
        }

        // Check if first bytes look like a message type (0x0b-0x0f, 0x00)
        let (msg_type, subtype, timestamp, payload_start, msg_len) =
            if header_buf[0] >= 0x0b && header_buf[0] <= 0x0f && header_buf[1] == 0x00 {
                // Type-first format: [type:1] [0x00:1] [subtype:2] [timestamp:4] [flags:4] [data...]
                let msg_type = header_buf[0];
                let subtype = u16::from_le_bytes([header_buf[2], header_buf[3]]) as u8;
                let timestamp = u32::from_le_bytes([
                    header_buf[4], header_buf[5], header_buf[6], header_buf[7]
                ]) as u64;
                let flags_or_len = u32::from_le_bytes([
                    header_buf[8], header_buf[9], header_buf[10], header_buf[11]
                ]);

                // Determine message length from flags or scan for next message
                let payload_len = if flags_or_len > 0 && flags_or_len < 4096 {
                    flags_or_len as usize
                } else {
                    // Scan for next message type marker
                    self.scan_for_message_length(12)?
                };

                (msg_type, subtype, timestamp, 12usize, payload_len)
            } else if header_buf[1] >= 0x0b && header_buf[1] <= 0x0f {
                // Alternative: length-prefixed format [len:1] [type:1] [subtype:2] ...
                let msg_len = header_buf[0] as usize;
                let msg_type = header_buf[1];
                let subtype = header_buf[2];
                let timestamp = u32::from_le_bytes([
                    header_buf[4], header_buf[5], header_buf[6], header_buf[7]
                ]) as u64;

                (msg_type, subtype, timestamp, 8usize, msg_len.saturating_sub(8))
            } else {
                // Unknown format - try to find next valid message
                if let Some(offset) = self.scan_for_next_message()? {
                    self.current_offset = offset;
                    return self.next_message();
                } else {
                    return Ok(None);
                }
            };

        // Cap payload at reasonable size
        let payload_len = msg_len.min(8192);

        // Read payload
        self.reader.seek(SeekFrom::Start(message_offset + payload_start as u64))?;
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            match self.reader.read(&mut payload) {
                Ok(n) => payload.truncate(n),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    payload.clear();
                }
                Err(e) => return Err(SdmParseError::IoError(e)),
            }
        }

        // Update offset for next message
        self.current_offset = self.reader.stream_position()?;

        let category = ((msg_type as u16) << 8) | (subtype as u16);

        Ok(Some(SdmMessage {
            offset: message_offset,
            timestamp,
            msg_type,
            subtype,
            category,
            payload,
        }))
    }

    /// Scan forward to find the length until the next message marker
    fn scan_for_message_length(&mut self, header_size: usize) -> Result<usize, SdmParseError> {
        let start_pos = self.reader.stream_position()?;
        let mut scan_buf = [0u8; 1024];
        let mut total_scanned = 0usize;

        loop {
            match self.reader.read(&mut scan_buf) {
                Ok(0) => break,
                Ok(n) => {
                    // Look for next message type marker
                    for i in 0..n.saturating_sub(1) {
                        if scan_buf[i] >= 0x0b && scan_buf[i] <= 0x0f && scan_buf[i + 1] == 0x00 {
                            // Found next message
                            self.reader.seek(SeekFrom::Start(start_pos))?;
                            return Ok(total_scanned + i - header_size);
                        }
                    }
                    total_scanned += n;
                    if total_scanned > 8192 {
                        break; // Cap search
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(SdmParseError::IoError(e)),
            }
        }

        self.reader.seek(SeekFrom::Start(start_pos))?;
        Ok(total_scanned.saturating_sub(header_size).min(4096))
    }

    /// Scan for the next valid message in the file
    fn scan_for_next_message(&mut self) -> Result<Option<u64>, SdmParseError> {
        let start_pos = self.reader.stream_position()?;
        let mut scan_buf = [0u8; 1024];
        let mut total_scanned = 0u64;

        loop {
            match self.reader.read(&mut scan_buf) {
                Ok(0) => return Ok(None),
                Ok(n) => {
                    for i in 0..n.saturating_sub(1) {
                        if scan_buf[i] >= 0x0b && scan_buf[i] <= 0x0f && scan_buf[i + 1] == 0x00 {
                            return Ok(Some(start_pos + total_scanned + i as u64));
                        }
                    }
                    total_scanned += n as u64;
                    if total_scanned > 65536 {
                        return Ok(None); // Give up after 64KB
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(SdmParseError::IoError(e)),
            }
        }
    }

    /// Iterate over all messages
    pub fn messages(&mut self) -> SdmMessageIterator<'_, R> {
        SdmMessageIterator { parser: self }
    }
}

pub struct SdmMessageIterator<'a, R: Read + Seek> {
    parser: &'a mut SdmParser<R>,
}

impl<'a, R: Read + Seek> Iterator for SdmMessageIterator<'a, R> {
    type Item = Result<SdmMessage, SdmParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.parser.next_message() {
            Ok(Some(msg)) => Some(Ok(msg)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Quick function to dump SDM file statistics
pub fn analyze_sdm_file<R: Read + Seek>(reader: R) -> Result<SdmStats, SdmParseError> {
    let mut parser = SdmParser::new(reader);
    let header = parser.parse_header()?;

    let mut stats = SdmStats {
        header,
        total_messages: 0,
        lte_rrc_messages: 0,
        lte_nas_messages: 0,
        nr_messages: 0,
        gsm_messages: 0,
        nas_messages: 0,
        debug_messages: 0,
        signaling_messages: 0,
        categories: std::collections::HashMap::new(),
    };

    for msg_result in parser.messages() {
        match msg_result {
            Ok(msg) => {
                stats.total_messages += 1;
                *stats.categories.entry(msg.category).or_insert(0) += 1;

                if msg.is_lte_rrc() {
                    stats.lte_rrc_messages += 1;
                }
                if msg.is_lte_nas() {
                    stats.lte_nas_messages += 1;
                }
                if msg.is_nr() {
                    stats.nr_messages += 1;
                }
                if msg.is_gsm() {
                    stats.gsm_messages += 1;
                }
                if msg.is_nas() {
                    stats.nas_messages += 1;
                }
                if msg.is_debug_log() {
                    stats.debug_messages += 1;
                }
                if msg.is_signaling() {
                    stats.signaling_messages += 1;
                }
            }
            Err(_) => break,
        }
    }

    Ok(stats)
}

/// SDM file statistics
#[derive(Debug)]
pub struct SdmStats {
    pub header: SdmHeader,
    pub total_messages: usize,
    pub lte_rrc_messages: usize,
    pub lte_nas_messages: usize,
    pub nr_messages: usize,
    pub gsm_messages: usize,
    pub nas_messages: usize,
    pub debug_messages: usize,
    pub signaling_messages: usize,
    pub categories: std::collections::HashMap<u16, usize>,
}

impl SdmStats {
    /// Get a summary string for display
    pub fn summary(&self) -> String {
        format!(
            "SDM File Analysis:\n\
             Logger: {}\n\
             Timezone: {}\n\
             Modem: {}\n\
             IMEI: {}\n\
             Total messages: {}\n\
             LTE RRC: {}\n\
             LTE NAS: {}\n\
             5G NR: {}\n\
             GSM: {}\n\
             Debug: {}\n\
             Signaling: {}",
            self.header.logger_version,
            self.header.timezone,
            self.header.modem_version.as_deref().unwrap_or("Unknown"),
            self.header.imei.as_deref().unwrap_or("Unknown"),
            self.total_messages,
            self.lte_rrc_messages,
            self.lte_nas_messages,
            self.nr_messages,
            self.gsm_messages,
            self.debug_messages,
            self.signaling_messages,
        )
    }
}

/// Convert an SDM message to a Shannon DmMessage for analysis pipeline integration
impl SdmMessage {
    /// Convert to Shannon DmMessage format
    pub fn to_dm_message(&self) -> crate::shannon::DmMessage {
        use crate::shannon::{DmLogCategory, DmMessageType, SipcRawHeader};

        // Map SDM category to Shannon category
        let shannon_category = match self.get_category() {
            SdmMessageCategory::LteRrc => DmLogCategory::LteRrc as u16 + self.subtype as u16,
            SdmMessageCategory::LteNas => DmLogCategory::LteNas as u16 + self.subtype as u16,
            SdmMessageCategory::Nr => DmLogCategory::NrRrc as u16 + self.subtype as u16,
            SdmMessageCategory::Gsm => DmLogCategory::GsmL2 as u16 + self.subtype as u16,
            SdmMessageCategory::Debug | SdmMessageCategory::Unknown => 0xFFFF,
        };

        crate::shannon::DmMessage {
            header: SipcRawHeader {
                channel: 28, // DM channel
                control: 0,
                len: self.payload.len() as u16,
            },
            msg_type: DmMessageType::Log,
            category: shannon_category,
            timestamp: self.timestamp,
            payload: self.payload.clone(),
        }
    }
}

/// Parse SDM file and convert to GSMTAP messages for analysis
pub fn parse_sdm_to_gsmtap<R: Read + Seek>(
    reader: R,
) -> Result<Vec<(u64, crate::gsmtap::GsmtapMessage)>, SdmParseError> {
    use crate::shannon_gsmtap_parser;

    let mut parser = SdmParser::new(reader);
    let _ = parser.parse_header()?;

    let mut gsmtap_messages = Vec::new();

    for msg_result in parser.messages() {
        match msg_result {
            Ok(msg) => {
                // Only process signaling messages
                if msg.is_signaling() {
                    let dm_msg = msg.to_dm_message();
                    if let Ok(Some((ts, gsmtap))) = shannon_gsmtap_parser::parse(&dm_msg) {
                        gsmtap_messages.push((ts.raw, gsmtap));
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ok(gsmtap_messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn create_test_sdm_data() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Header: length (2 bytes) + magic (4 bytes)
        data[0] = 0x3d; // Length low byte
        data[1] = 0x00; // Length high byte
        data[2] = 0x39; // Magic bytes (0x0004fd39)
        data[3] = 0xfd;
        data[4] = 0x04;
        data[5] = 0x00;

        // Logger version at offset 0x0a
        let version = b"Pixel Logger Ver. 1 Jun. 10,2021";
        data[0x0a..0x0a + version.len()].copy_from_slice(version);

        // Timezone at offset 0x38
        let tz = b"Etc/GMT";
        data[0x38..0x38 + tz.len()].copy_from_slice(tz);

        // Add a test message at offset 0x140
        let msg_offset = 0x140;
        data.resize(msg_offset + 32, 0);
        data[msg_offset] = 0x0b; // LTE RRC type
        data[msg_offset + 1] = 0x00;
        data[msg_offset + 2] = 0x01; // Subtype
        data[msg_offset + 3] = 0x00;
        data[msg_offset + 4] = 0x66; // Timestamp "fD"
        data[msg_offset + 5] = 0x44;
        data[msg_offset + 6] = 0x00;
        data[msg_offset + 7] = 0x00;
        // Payload follows

        data
    }

    #[test]
    fn test_sdm_header_parsing() {
        let data = create_test_sdm_data();
        let mut parser = SdmParser::new(Cursor::new(data));

        let result = parser.parse_header();
        assert!(result.is_ok());

        let header = result.unwrap();
        assert!(header.logger_version.contains("Pixel Logger"));
        assert_eq!(header.timezone, "Etc/GMT");
    }

    #[test]
    fn test_sdm_message_category() {
        let msg = SdmMessage {
            offset: 0,
            timestamp: 0,
            msg_type: 0x0b,
            subtype: 0x01,
            category: 0x0b01,
            payload: vec![],
        };

        assert!(msg.is_lte_rrc());
        assert!(!msg.is_lte_nas());
        assert!(!msg.is_debug_log());
        assert!(msg.is_signaling());
    }

    #[test]
    fn test_sdm_message_parsing() {
        let data = create_test_sdm_data();
        let mut parser = SdmParser::new(Cursor::new(data));

        // Parse header first
        let _ = parser.parse_header();

        // Try to read a message
        let result = parser.next_message();
        assert!(result.is_ok());

        if let Ok(Some(msg)) = result {
            assert_eq!(msg.msg_type, 0x0b);
            assert!(msg.is_lte_rrc());
        }
    }

    #[test]
    fn test_sdm_category_enum() {
        assert_eq!(SdmMessageCategory::from(0x0b), SdmMessageCategory::LteRrc);
        assert_eq!(SdmMessageCategory::from(0x0c), SdmMessageCategory::LteNas);
        assert_eq!(SdmMessageCategory::from(0x0d), SdmMessageCategory::Nr);
        assert_eq!(SdmMessageCategory::from(0x0e), SdmMessageCategory::Gsm);
        assert_eq!(SdmMessageCategory::from(0x0f), SdmMessageCategory::Debug);
        assert_eq!(SdmMessageCategory::from(0xff), SdmMessageCategory::Unknown);
    }
}
