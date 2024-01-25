use std::io;
use std::path::Path;

use bytes::BytesMut;
use sha2::digest::generic_array::GenericArray;
use sha2::digest::typenum::{Unsigned, U32};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Eq, PartialEq)]
pub struct Checksum(GenericArray<u8, U32>);

impl Checksum {
    pub async fn compute_from_file(file_path: &Path) -> io::Result<Self> {
        log::debug!("Computing checksum for file: {file_path:?}");

        let input_file = tokio::fs::File::open(file_path).await?;
        let reader = tokio::io::BufReader::new(input_file);

        Self::compute_from_stream(reader).await
    }

    async fn compute_from_stream<S: AsyncRead + Unpin>(mut reader: S) -> io::Result<Self> {
        const ONE_MB: usize = 1024 * 1024;
        let mut sha = Sha256::new();
        let mut buf = BytesMut::with_capacity(ONE_MB);
        loop {
            buf.clear();
            let len = reader.read_buf(&mut buf).await?;
            if len == 0 {
                break;
            }
            sha.update(&buf[0..len]);
        }
        Ok(Self(sha.finalize()))
    }

    pub fn parse(hash: &str) -> io::Result<Self> {
        let hash = hex::decode(hash)
            .map_err(|e| io::Error::other(format!("Unable to hex decode checksum: {}", e)))?;
        if hash.len() != U32::USIZE {
            return Err(io::Error::other(format!(
                "Unable to construct checksum from array of length {}",
                hash.len()
            )));
        }
        Ok(Self(*GenericArray::<u8, U32>::from_slice(&hash)))
    }

    pub async fn matches_file(&self, file_path: &Path) -> io::Result<bool> {
        let file_checksum = Checksum::compute_from_file(file_path).await?;
        Ok(&file_checksum == self)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}
