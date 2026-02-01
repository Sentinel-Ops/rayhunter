//! Shannon Mobile Diagnostic Log (SMDL) file format
//!
//! SMDL files store diagnostic messages from Samsung Shannon modems.
//! Similar to QMDL (Qualcomm Mobile Diagnostic Log), but for Samsung devices.
//!
//! File format:
//! - Magic bytes: "SMDL" (4 bytes)
//! - Version: u32 (4 bytes)
//! - Device info length: u32 (4 bytes)
//! - Device info: UTF-8 string
//! - Messages: concatenated SipcRawHeader + payload pairs

use crate::shannon::{DmMessage, DmMessagesContainer, SipcRawHeader};

use futures::TryStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Magic bytes identifying an SMDL file
pub const SMDL_MAGIC: &[u8; 4] = b"SMDL";

/// Current SMDL format version
pub const SMDL_VERSION: u32 = 1;

/// SMDL file header
#[derive(Debug, Clone)]
pub struct SmdlHeader {
    pub version: u32,
    pub device_info: String,
}

impl SmdlHeader {
    pub fn new(device_info: String) -> Self {
        Self {
            version: SMDL_VERSION,
            device_info,
        }
    }

    /// Calculate the total header size in bytes
    pub fn size(&self) -> usize {
        4 + // magic
        4 + // version
        4 + // device_info length
        self.device_info.len()
    }
}

/// Writer for SMDL files
pub struct SmdlWriter<T>
where
    T: AsyncWrite + Unpin,
{
    writer: T,
    pub total_written: usize,
    header_written: bool,
}

impl<T> SmdlWriter<T>
where
    T: AsyncWrite + Unpin,
{
    pub fn new(writer: T) -> Self {
        SmdlWriter {
            writer,
            total_written: 0,
            header_written: false,
        }
    }

    pub fn new_with_existing_size(writer: T, existing_size: usize) -> Self {
        SmdlWriter {
            writer,
            total_written: existing_size,
            header_written: existing_size > 0,
        }
    }

    /// Write the file header (must be called before writing messages)
    pub async fn write_header(&mut self, header: &SmdlHeader) -> std::io::Result<()> {
        if self.header_written {
            return Ok(());
        }

        // Magic bytes
        self.writer.write_all(SMDL_MAGIC).await?;
        self.total_written += 4;

        // Version
        self.writer.write_all(&header.version.to_le_bytes()).await?;
        self.total_written += 4;

        // Device info length
        let info_len = header.device_info.len() as u32;
        self.writer.write_all(&info_len.to_le_bytes()).await?;
        self.total_written += 4;

        // Device info
        self.writer.write_all(header.device_info.as_bytes()).await?;
        self.total_written += header.device_info.len();

        self.header_written = true;
        Ok(())
    }

    /// Write a container of DM messages
    pub async fn write_container(
        &mut self,
        container: &DmMessagesContainer,
    ) -> std::io::Result<()> {
        for msg in &container.messages {
            self.write_message(msg).await?;
        }
        Ok(())
    }

    /// Write a single DM message
    pub async fn write_message(&mut self, msg: &DmMessage) -> std::io::Result<()> {
        // Write raw header
        self.writer.write_all(&[msg.header.channel]).await?;
        self.writer.write_all(&[msg.header.control]).await?;
        self.writer.write_all(&msg.header.len.to_le_bytes()).await?;
        self.total_written += SipcRawHeader::SIZE;

        // Write message metadata
        let msg_type_byte = match &msg.msg_type {
            crate::shannon::DmMessageType::Log => 0x10,
            crate::shannon::DmMessageType::Response => 0x11,
            crate::shannon::DmMessageType::Event => 0x12,
            crate::shannon::DmMessageType::Debug => 0x13,
            crate::shannon::DmMessageType::Unknown(v) => *v,
        };
        self.writer.write_all(&[msg_type_byte]).await?;
        self.writer.write_all(&msg.category.to_le_bytes()).await?;
        self.writer.write_all(&msg.timestamp.to_le_bytes()).await?;
        self.total_written += 11;

        // Write payload
        self.writer.write_all(&msg.payload).await?;
        self.total_written += msg.payload.len();

        Ok(())
    }
}

/// Reader for SMDL files
pub struct SmdlReader<T>
where
    T: AsyncRead,
{
    reader: BufReader<T>,
    bytes_read: usize,
    max_bytes: Option<usize>,
    header: Option<SmdlHeader>,
}

impl<T> SmdlReader<T>
where
    T: AsyncRead + Unpin,
{
    pub fn new(reader: T, max_bytes: Option<usize>) -> Self {
        SmdlReader {
            reader: BufReader::new(reader),
            bytes_read: 0,
            max_bytes,
            header: None,
        }
    }

    /// Read and validate the file header
    pub async fn read_header(&mut self) -> Result<SmdlHeader, std::io::Error> {
        if let Some(ref header) = self.header {
            return Ok(header.clone());
        }

        // Read magic
        let mut magic = [0u8; 4];
        self.reader.read_exact(&mut magic).await?;
        self.bytes_read += 4;

        if &magic != SMDL_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid SMDL magic: expected {:?}, got {:?}",
                    SMDL_MAGIC, magic
                ),
            ));
        }

        // Read version
        let mut version_bytes = [0u8; 4];
        self.reader.read_exact(&mut version_bytes).await?;
        self.bytes_read += 4;
        let version = u32::from_le_bytes(version_bytes);

        if version > SMDL_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Unsupported SMDL version: {}, max supported: {}",
                    version, SMDL_VERSION
                ),
            ));
        }

        // Read device info length
        let mut info_len_bytes = [0u8; 4];
        self.reader.read_exact(&mut info_len_bytes).await?;
        self.bytes_read += 4;
        let info_len = u32::from_le_bytes(info_len_bytes) as usize;

        // Read device info
        let mut device_info_bytes = vec![0u8; info_len];
        self.reader.read_exact(&mut device_info_bytes).await?;
        self.bytes_read += info_len;

        let device_info = String::from_utf8(device_info_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let header = SmdlHeader {
            version,
            device_info,
        };
        self.header = Some(header.clone());
        Ok(header)
    }

    /// Create an async stream of message containers
    pub fn as_stream(
        &mut self,
    ) -> impl TryStream<Ok = DmMessagesContainer, Error = std::io::Error> + '_ {
        futures::stream::try_unfold(self, |reader| async {
            let maybe_container = reader.get_next_messages_container().await?;
            match maybe_container {
                Some(container) => Ok(Some((container, reader))),
                None => Ok(None),
            }
        })
    }

    /// Read the next message container
    pub async fn get_next_messages_container(
        &mut self,
    ) -> Result<Option<DmMessagesContainer>, std::io::Error> {
        // Ensure header is read first
        if self.header.is_none() {
            self.read_header().await?;
        }

        if let Some(max_bytes) = self.max_bytes {
            if self.bytes_read >= max_bytes {
                return Ok(None);
            }
        }

        // Try to read a raw header
        let mut header_bytes = [0u8; 4];
        match self.reader.read_exact(&mut header_bytes).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
        self.bytes_read += 4;

        let channel = header_bytes[0];
        let control = header_bytes[1];
        let len = u16::from_le_bytes([header_bytes[2], header_bytes[3]]);

        // Read message metadata (11 bytes)
        let mut meta_bytes = [0u8; 11];
        self.reader.read_exact(&mut meta_bytes).await?;
        self.bytes_read += 11;

        let msg_type = match meta_bytes[0] {
            0x10 => crate::shannon::DmMessageType::Log,
            0x11 => crate::shannon::DmMessageType::Response,
            0x12 => crate::shannon::DmMessageType::Event,
            0x13 => crate::shannon::DmMessageType::Debug,
            v => crate::shannon::DmMessageType::Unknown(v),
        };
        let category = u16::from_le_bytes([meta_bytes[1], meta_bytes[2]]);
        let timestamp = u64::from_le_bytes([
            meta_bytes[3],
            meta_bytes[4],
            meta_bytes[5],
            meta_bytes[6],
            meta_bytes[7],
            meta_bytes[8],
            meta_bytes[9],
            meta_bytes[10],
        ]);

        // Calculate payload length (total - metadata)
        let payload_len = if len as usize > 11 {
            len as usize - 11
        } else {
            0
        };

        // Read payload
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            self.reader.read_exact(&mut payload).await?;
            self.bytes_read += payload_len;
        }

        let msg = DmMessage {
            header: SipcRawHeader {
                channel,
                control,
                len,
            },
            msg_type,
            category,
            timestamp,
            payload,
        };

        let mut container = DmMessagesContainer::new();
        container.push(msg);
        Ok(Some(container))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn get_test_header() -> SmdlHeader {
        SmdlHeader::new("Pixel 9 (tokay)".to_string())
    }

    fn get_test_message() -> DmMessage {
        DmMessage {
            header: SipcRawHeader {
                channel: 28,
                control: 0,
                len: 20,
            },
            msg_type: crate::shannon::DmMessageType::Log,
            category: 0x3000, // LTE RRC
            timestamp: 1234567890,
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        }
    }

    #[tokio::test]
    async fn test_write_and_read_header() {
        let mut buf = Vec::new();
        let mut writer = SmdlWriter::new(&mut buf);
        let header = get_test_header();

        writer.write_header(&header).await.unwrap();

        let mut reader = SmdlReader::new(Cursor::new(&buf), None);
        let read_header = reader.read_header().await.unwrap();

        assert_eq!(read_header.version, header.version);
        assert_eq!(read_header.device_info, header.device_info);
    }

    #[tokio::test]
    async fn test_write_and_read_message() {
        let mut buf = Vec::new();
        let mut writer = SmdlWriter::new(&mut buf);
        let header = get_test_header();
        let msg = get_test_message();

        writer.write_header(&header).await.unwrap();
        writer.write_message(&msg).await.unwrap();

        let mut reader = SmdlReader::new(Cursor::new(&buf), None);
        let _ = reader.read_header().await.unwrap();
        let container = reader.get_next_messages_container().await.unwrap().unwrap();

        assert_eq!(container.messages.len(), 1);
        assert_eq!(container.messages[0].category, msg.category);
        assert_eq!(container.messages[0].payload, msg.payload);
    }
}
