//! Samsung Shannon IPC/DM protocol serialization/deserialization
//!
//! This module implements the Samsung Inter-Processor Communication (SIPC) protocol
//! used by Samsung Shannon modems found in Google Pixel 6+ devices.
//!
//! References:
//! - libsamsung-ipc: https://github.com/morphis/libsamsung-ipc
//! - Replicant: https://redmine.replicant.us/projects/replicant/wiki/libsamsung-ipc
//! - Samsung kernel sources: modem_prj.h, modem-s5000ap-sipc-pdata.dtsi

use deku::prelude::*;
use thiserror::Error;

/// HDLC frame start marker for Samsung IPC
pub const SIPC_FRAME_START: u8 = 0x7f;

/// SIPC5 protocol version
pub const SIPC_VERSION: u8 = 5;

/// IPC command types
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum IpcCmdType {
    #[deku(id = "0x01")]
    Exec,
    #[deku(id = "0x02")]
    Get,
    #[deku(id = "0x03")]
    Set,
    #[deku(id = "0x04")]
    Confirm,
    #[deku(id = "0x05")]
    Event,
    #[deku(id = "0x06")]
    Notification,
    #[deku(id_pat = "_")]
    Unknown(u8),
}

/// IPC main command groups
#[derive(Debug, Clone, Copy, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum IpcMainCmd {
    #[deku(id = "0x01")]
    Power,
    #[deku(id = "0x02")]
    Call,
    #[deku(id = "0x03")]
    Sms,
    #[deku(id = "0x04")]
    Sec,
    #[deku(id = "0x05")]
    Pb,
    #[deku(id = "0x06")]
    Disp,
    #[deku(id = "0x07")]
    Net,
    #[deku(id = "0x08")]
    Snd,
    #[deku(id = "0x09")]
    Misc,
    #[deku(id = "0x0A")]
    Svc,
    #[deku(id = "0x0B")]
    Ss,
    #[deku(id = "0x0C")]
    Gprs,
    #[deku(id = "0x0D")]
    Sat,
    #[deku(id = "0x0E")]
    Cfg,
    #[deku(id = "0x0F")]
    Imei,
    #[deku(id = "0x10")]
    Gps,
    #[deku(id = "0x11")]
    Omadm,
    #[deku(id = "0x80")]
    Gen,
    #[deku(id = "0xFE")]
    Rfs,
    #[deku(id_pat = "_")]
    Unknown(u8),
}

/// SIPC Format Header (7 bytes)
/// Used for formatted IPC messages on /dev/umts_ipc0
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct SipcFmtHeader {
    /// Total message length including header
    pub len: u16,
    /// Message sequence number
    pub msg_seq: u8,
    /// Acknowledgment sequence number
    pub ack_seq: u8,
    /// Main command group
    pub main_cmd: u8,
    /// Sub command within group
    pub sub_cmd: u8,
    /// Command type (exec/get/set/etc)
    pub cmd_type: u8,
}

impl SipcFmtHeader {
    pub const SIZE: usize = 7;

    pub fn new(main_cmd: u8, sub_cmd: u8, cmd_type: IpcCmdType, msg_seq: u8) -> Self {
        Self {
            len: 0, // Will be set when payload is known
            msg_seq,
            ack_seq: 0,
            main_cmd,
            sub_cmd,
            cmd_type: match cmd_type {
                IpcCmdType::Exec => 0x01,
                IpcCmdType::Get => 0x02,
                IpcCmdType::Set => 0x03,
                IpcCmdType::Confirm => 0x04,
                IpcCmdType::Event => 0x05,
                IpcCmdType::Notification => 0x06,
                IpcCmdType::Unknown(v) => v,
            },
        }
    }
}

/// SIPC5 Raw Header for DM (Diagnostic Monitor) channel
/// Used on /dev/umts_dm0 for diagnostic data
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(endian = "little")]
pub struct SipcRawHeader {
    /// Channel ID (28 for umts_dm0)
    pub channel: u8,
    /// Control byte (multi-frame: 0x80 = more frames, 0x7F = frame ID mask)
    pub control: u8,
    /// Length of data following this header
    pub len: u16,
}

impl SipcRawHeader {
    pub const SIZE: usize = 4;
    pub const DM_CHANNEL_ID: u8 = 28;

    /// Check if this is a multi-frame message with more frames following
    pub fn has_more_frames(&self) -> bool {
        (self.control & 0x80) != 0
    }

    /// Get the frame ID for multi-frame reassembly
    pub fn frame_id(&self) -> u8 {
        self.control & 0x7F
    }
}

/// Samsung Diagnostic Monitor message types
/// Based on analysis of Samsung modem diagnostic protocols
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum DmMessageType {
    /// Log message containing protocol data
    #[deku(id = "0x10")]
    Log,
    /// Response to a command
    #[deku(id = "0x11")]
    Response,
    /// Event notification
    #[deku(id = "0x12")]
    Event,
    /// Debug/trace message
    #[deku(id = "0x13")]
    Debug,
    #[deku(id_pat = "_")]
    Unknown(u8),
}

/// Diagnostic Monitor Log Categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DmLogCategory {
    /// GSM/GPRS Layer 2 signalling
    GsmL2 = 0x1000,
    /// GSM/GPRS Layer 3 signalling
    GsmL3 = 0x1100,
    /// WCDMA/UMTS signalling
    Wcdma = 0x2000,
    /// LTE RRC signalling
    LteRrc = 0x3000,
    /// LTE NAS signalling
    LteNas = 0x3100,
    /// 5G NR RRC signalling
    NrRrc = 0x4000,
    /// 5G NR NAS signalling
    NrNas = 0x4100,
    /// IP traffic
    IpTraffic = 0x5000,
}

/// A parsed Samsung DM message
#[derive(Debug, Clone, PartialEq)]
pub struct DmMessage {
    pub header: SipcRawHeader,
    pub msg_type: DmMessageType,
    pub category: u16,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

/// Container for multiple DM messages read from device
#[derive(Debug, Clone, PartialEq)]
pub struct DmMessagesContainer {
    pub messages: Vec<DmMessage>,
}

impl DmMessagesContainer {
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    pub fn push(&mut self, msg: DmMessage) {
        self.messages.push(msg);
    }
}

impl Default for DmMessagesContainer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum ShannonParsingError {
    #[error("Failed to parse SIPC header: {0}")]
    HeaderParsingError(String),
    #[error("Failed to parse DM message: {0}, data: {1:?}")]
    MessageParsingError(String, Vec<u8>),
    #[error("Invalid channel ID: expected {expected}, got {got}")]
    InvalidChannel { expected: u8, got: u8 },
    #[error("Buffer too small: need {need} bytes, got {got}")]
    BufferTooSmall { need: usize, got: usize },
    #[error("Checksum mismatch")]
    ChecksumError,
}

/// Parse raw bytes from /dev/umts_dm0 into DM messages
pub fn parse_dm_buffer(data: &[u8]) -> Result<Vec<DmMessage>, ShannonParsingError> {
    let mut messages = Vec::new();
    let mut offset = 0;

    while offset + SipcRawHeader::SIZE <= data.len() {
        // Parse header
        let header_bytes = &data[offset..offset + SipcRawHeader::SIZE];
        let header = match SipcRawHeader::from_bytes((header_bytes, 0)) {
            Ok((_, h)) => h,
            Err(e) => {
                return Err(ShannonParsingError::HeaderParsingError(format!("{:?}", e)));
            }
        };

        let msg_start = offset + SipcRawHeader::SIZE;
        let msg_end = msg_start + header.len as usize;

        if msg_end > data.len() {
            return Err(ShannonParsingError::BufferTooSmall {
                need: msg_end,
                got: data.len(),
            });
        }

        let payload = data[msg_start..msg_end].to_vec();

        // Parse message type and category from payload if available
        let (msg_type, category, timestamp, actual_payload) = if payload.len() >= 11 {
            let msg_type = match payload[0] {
                0x10 => DmMessageType::Log,
                0x11 => DmMessageType::Response,
                0x12 => DmMessageType::Event,
                0x13 => DmMessageType::Debug,
                v => DmMessageType::Unknown(v),
            };
            let category = u16::from_le_bytes([payload[1], payload[2]]);
            let timestamp = u64::from_le_bytes([
                payload[3],
                payload[4],
                payload[5],
                payload[6],
                payload[7],
                payload[8],
                payload[9],
                payload[10],
            ]);
            (msg_type, category, timestamp, payload[11..].to_vec())
        } else {
            (DmMessageType::Unknown(0), 0, 0, payload)
        };

        messages.push(DmMessage {
            header,
            msg_type,
            category,
            timestamp,
            payload: actual_payload,
        });

        offset = msg_end;
    }

    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sipc_fmt_header_size() {
        assert_eq!(SipcFmtHeader::SIZE, 7);
    }

    #[test]
    fn test_sipc_raw_header_size() {
        assert_eq!(SipcRawHeader::SIZE, 4);
    }

    #[test]
    fn test_sipc_raw_header_parsing() {
        // Channel 28 (DM), no more frames, length 100
        let data = vec![28, 0x00, 100, 0];
        let (_, header) = SipcRawHeader::from_bytes((&data, 0)).unwrap();
        assert_eq!(header.channel, 28);
        assert!(!header.has_more_frames());
        assert_eq!(header.len, 100);
    }

    #[test]
    fn test_sipc_raw_header_multiframe() {
        // Channel 28, more frames (0x80), frame ID 5, length 50
        let data = vec![28, 0x85, 50, 0];
        let (_, header) = SipcRawHeader::from_bytes((&data, 0)).unwrap();
        assert!(header.has_more_frames());
        assert_eq!(header.frame_id(), 5);
    }
}
