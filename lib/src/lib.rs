use serde::{Deserialize, Serialize};

pub mod analysis;
pub mod diag;
pub mod gsmtap;
pub mod gsmtap_parser;
pub mod hdlc;
pub mod log_codes;
pub mod pcap;
pub mod qmdl;
pub mod smdl;
pub mod util;

// Samsung Shannon modem support (Google Pixel 6+)
pub mod shannon;

// bin/check.rs may target windows and does not use this mod
#[cfg(target_family = "unix")]
pub mod diag_device;

// Samsung Shannon device interface (Google Pixel 6+)
#[cfg(target_family = "unix")]
pub mod shannon_device;

// re-export telcom_parser, since we use its types in our API
pub use telcom_parser;

/// Supported device types
#[derive(PartialEq, Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Device {
    Orbic,
    Tplink,
    Tmobile,
    Wingtech,
    Pinephone,
    Uz801,
    // Google Pixel devices with Samsung Shannon modem
    Pixel9,
}

/// Modem types used by devices
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ModemType {
    /// Qualcomm modem with DIAG protocol (/dev/diag)
    Qualcomm,
    /// Samsung Shannon modem with SIPC protocol (/dev/umts_dm0)
    Shannon,
}

impl Device {
    /// Get the modem type for this device
    pub fn modem_type(&self) -> ModemType {
        match self {
            Device::Pixel9 => ModemType::Shannon,
            _ => ModemType::Qualcomm,
        }
    }

    /// Check if this device uses a Samsung Shannon modem
    pub fn is_shannon(&self) -> bool {
        matches!(self.modem_type(), ModemType::Shannon)
    }

    /// Check if this device uses a Qualcomm modem
    pub fn is_qualcomm(&self) -> bool {
        matches!(self.modem_type(), ModemType::Qualcomm)
    }
}
