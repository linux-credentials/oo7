use std::io::Read;

use crate::error::{Error, Result};

/// Qt's QDataStream reader (big-endian)
pub struct QDataStreamReader<R> {
    reader: R,
}

impl<R: Read> QDataStreamReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    pub fn read_i32(&mut self) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(i32::from_be_bytes(buf))
    }

    /// Read QString (UTF-16 BE)
    pub fn read_string(&mut self) -> Result<String> {
        let byte_length = self.read_u32()? as usize;

        if byte_length == 0xffffffff {
            return Ok(String::new());
        }

        if !byte_length.is_multiple_of(2) {
            return Err(Error::InvalidDataStructure);
        }

        let mut utf16_buf = vec![0u16; byte_length / 2];
        for item in &mut utf16_buf {
            *item = self.read_u16()?;
        }

        String::from_utf16(&utf16_buf).map_err(|_| Error::InvalidDataStructure)
    }

    /// Read QByteArray
    pub fn read_byte_array(&mut self) -> Result<Vec<u8>> {
        let byte_length = self.read_u32()? as usize;

        if byte_length == 0xffffffff {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; byte_length];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_raw(&mut self, buf: &mut [u8]) -> Result<()> {
        self.reader.read_exact(buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_read_string() {
        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(&[0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F]);

        let mut reader = QDataStreamReader::new(Cursor::new(data));
        assert_eq!(reader.read_string().unwrap(), "hello");
    }
}
