//! Samsung Shannon modem device interface
//!
//! This module provides access to Samsung Shannon modems via /dev/umts_dm0
//! (Diagnostic Monitor) interface, found in Google Pixel 6+ devices.
//!
//! Device configuration from Samsung kernel device tree:
//! - Device: /dev/umts_dm0
//! - Channel ID: 28
//! - Format: IPC_RAW (1)
//! - IO Type: IODEV_MISC (0)
//! - Attrs: ATTR_SBD_IPC | ATTR_SIPC5 (0x82)
//! - Upload buffers: 16 x 2048 bytes
//! - Download buffers: 128 x 2048 bytes

use crate::shannon::{DmMessagesContainer, ShannonParsingError, parse_dm_buffer};

use futures::TryStream;
use log::{debug, error, info, warn};
use std::os::fd::AsRawFd;
use std::time::Duration;
use thiserror::Error;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

pub type ShannonResult<T> = Result<T, ShannonDeviceError>;

#[derive(Error, Debug)]
pub enum ShannonDeviceError {
    #[error("Failed to initialize Shannon device: {0}")]
    InitializationFailed(String),
    #[error("Failed to read Shannon device: {0}")]
    DeviceReadFailed(std::io::Error),
    #[error("Failed to write Shannon device: {0}")]
    DeviceWriteFailed(std::io::Error),
    #[error("Failed to open Shannon DM device: {0}")]
    OpenDeviceError(std::io::Error),
    #[error("Failed to parse DM messages: {0}")]
    ParseError(#[from] ShannonParsingError),
    #[error("Device not supported: {0}")]
    UnsupportedDevice(String),
    #[error("Permission denied accessing {0}")]
    PermissionDenied(String),
}

/// Path to the Samsung Shannon Diagnostic Monitor device
pub const SHANNON_DM_DEVICE: &str = "/dev/umts_dm0";

/// Alternative paths that might exist on some devices
pub const SHANNON_DM_DEVICE_ALT: &[&str] = &["/dev/umts_dm0", "/dev/samsung_dm0", "/dev/modem_dm0"];

/// Buffer size for reading from DM device
/// Based on Samsung kernel config: 128 buffers x 2048 bytes
const BUFFER_LEN: usize = 128 * 2048;

/// Samsung Shannon modem diagnostic interface
pub struct ShannonDevice {
    file: File,
    read_buf: Vec<u8>,
    device_path: String,
}

impl ShannonDevice {
    /// Create a new Shannon device connection with default timeout
    pub async fn new() -> ShannonResult<Self> {
        Self::new_with_retries(Duration::from_secs(30)).await
    }

    /// Create a new Shannon device connection with custom timeout and retries
    pub async fn new_with_retries(max_duration: Duration) -> ShannonResult<Self> {
        let start_time = std::time::Instant::now();
        let max_delay = Duration::from_secs(5);
        let mut delay = Duration::from_millis(100);
        let mut num_retries = 0;

        loop {
            match Self::try_new().await {
                Ok(device) => {
                    info!("Shannon device initialization succeeded after {num_retries} retries");
                    return Ok(device);
                }
                Err(e) => {
                    num_retries += 1;
                    if start_time.elapsed() >= max_duration {
                        error!("Failed to initialize Shannon device after {max_duration:?}: {e}");
                        return Err(e);
                    }

                    info!(
                        "Shannon device initialization failed {num_retries} times, retrying in {delay:?}: {e}"
                    );
                    sleep(delay).await;

                    // Exponential backoff
                    delay = std::cmp::min(delay * 2, max_delay);
                }
            }
        }
    }

    /// Attempt to open the Shannon DM device
    async fn try_new() -> ShannonResult<Self> {
        // Try each possible device path
        for device_path in std::iter::once(&SHANNON_DM_DEVICE).chain(SHANNON_DM_DEVICE_ALT.iter()) {
            match Self::open_device(device_path).await {
                Ok(device) => return Ok(device),
                Err(ShannonDeviceError::OpenDeviceError(ref e))
                    if e.kind() == std::io::ErrorKind::NotFound =>
                {
                    debug!("Device {device_path} not found, trying next...");
                    continue;
                }
                Err(e) => {
                    warn!("Failed to open {device_path}: {e}");
                    continue;
                }
            }
        }

        Err(ShannonDeviceError::InitializationFailed(
            "No Samsung Shannon DM device found. Tried: /dev/umts_dm0 and alternatives."
                .to_string(),
        ))
    }

    /// Open a specific device path
    async fn open_device(device_path: &str) -> ShannonResult<Self> {
        info!("Attempting to open Shannon DM device at {device_path}");

        let file = File::options()
            .read(true)
            .write(true)
            .open(device_path)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    ShannonDeviceError::PermissionDenied(device_path.to_string())
                } else {
                    ShannonDeviceError::OpenDeviceError(e)
                }
            })?;

        let fd = file.as_raw_fd();
        info!("Opened Shannon DM device {device_path} with fd={fd}");

        // TODO: May need to send initialization commands to enable diagnostic logging
        // This depends on Samsung's proprietary protocol

        Ok(ShannonDevice {
            file,
            read_buf: vec![0; BUFFER_LEN],
            device_path: device_path.to_string(),
        })
    }

    /// Get the device path being used
    pub fn device_path(&self) -> &str {
        &self.device_path
    }

    /// Create an async stream of DM message containers
    pub fn as_stream(
        &mut self,
    ) -> impl TryStream<Ok = DmMessagesContainer, Error = ShannonDeviceError> + '_ {
        futures::stream::try_unfold(self, |dev| async {
            let container = dev.read_messages().await?;
            Ok(Some((container, dev)))
        })
    }

    /// Read the next batch of DM messages from the device
    pub async fn read_messages(&mut self) -> ShannonResult<DmMessagesContainer> {
        let mut bytes_read = 0;

        // Keep reading until we have enough data
        while bytes_read < 4 {
            bytes_read = self
                .file
                .read(&mut self.read_buf)
                .await
                .map_err(ShannonDeviceError::DeviceReadFailed)?;

            if bytes_read == 0 {
                // No data available, small sleep to avoid busy loop
                sleep(Duration::from_millis(10)).await;
            }
        }

        debug!(
            "Read {} bytes from Shannon DM device: {:02x?}",
            bytes_read,
            &self.read_buf[0..std::cmp::min(32, bytes_read)]
        );

        let messages = parse_dm_buffer(&self.read_buf[0..bytes_read])?;

        let mut container = DmMessagesContainer::new();
        for msg in messages {
            container.push(msg);
        }

        Ok(container)
    }

    /// Write a command to the DM device
    pub async fn write_command(&mut self, data: &[u8]) -> ShannonResult<()> {
        debug!("Writing {} bytes to Shannon DM device", data.len());

        self.file
            .write_all(data)
            .await
            .map_err(ShannonDeviceError::DeviceWriteFailed)?;

        self.file
            .flush()
            .await
            .map_err(ShannonDeviceError::DeviceWriteFailed)?;

        Ok(())
    }

    /// Enable diagnostic logging on the modem
    /// This sends the necessary commands to start receiving diagnostic messages
    pub async fn enable_logging(&mut self) -> ShannonResult<()> {
        info!("Enabling Shannon diagnostic logging...");

        // TODO: Implement Samsung-specific logging enable commands
        // This requires reverse-engineering the Samsung DM protocol
        //
        // Potential approaches:
        // 1. Capture and replay commands from Samsung's diagnostic tools
        // 2. Analyze libsamsung-ipc for relevant command sequences
        // 3. Use AT commands via /dev/umts_ipc0 to enable diag mode

        warn!("Shannon logging enable not yet implemented - device may need manual configuration");

        Ok(())
    }

    /// Disable diagnostic logging
    pub async fn disable_logging(&mut self) -> ShannonResult<()> {
        info!("Disabling Shannon diagnostic logging...");

        // TODO: Send disable commands

        Ok(())
    }
}

/// Check if a Samsung Shannon modem is available on this device
pub async fn is_shannon_available() -> bool {
    for device_path in std::iter::once(&SHANNON_DM_DEVICE).chain(SHANNON_DM_DEVICE_ALT.iter()) {
        if tokio::fs::metadata(device_path).await.is_ok() {
            return true;
        }
    }
    false
}

/// Get information about the available Shannon device
pub async fn get_device_info() -> Option<String> {
    for device_path in std::iter::once(&SHANNON_DM_DEVICE).chain(SHANNON_DM_DEVICE_ALT.iter()) {
        if let Ok(metadata) = tokio::fs::metadata(device_path).await {
            return Some(format!(
                "Shannon DM device at {} (permissions: {:?})",
                device_path,
                metadata.permissions()
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_path_constant() {
        assert_eq!(SHANNON_DM_DEVICE, "/dev/umts_dm0");
    }

    #[test]
    fn test_buffer_size() {
        // 128 * 2048 = 262144
        assert_eq!(BUFFER_LEN, 262144);
    }
}
