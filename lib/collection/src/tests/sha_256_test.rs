use std::io::Write;

use tempfile::NamedTempFile;

use crate::common::sha_256::Checksum;

#[tokio::test]
async fn test_sha_256_digest() -> std::io::Result<()> {
    let mut file = NamedTempFile::new()?;
    write!(file, "This tests if the hashing a file works correctly.")?;
    let result_hash = Checksum::compute_from_file(file.path()).await?;
    assert_eq!(
        result_hash.hex(),
        "735e3ec1b05d901d07e84b1504518442aba2395fe3f945a1c962e81a8e152b2d"
    );
    Ok(())
}

#[tokio::test]
async fn test_parse_sha_256_from_non_hex_string_should_fail() -> std::io::Result<()> {
    // invalid sha256: last character is 'z'
    let invalid_sha256 = "735e3ec1b05d901d07e84b1504518442aba2395fe3f945a1c962e81a8e152b2z";

    assert!(Checksum::parse(invalid_sha256).is_err());
    Ok(())
}

#[tokio::test]
async fn test_parse_sha_256_from_non_string_of_invalid_len_should_fail() -> std::io::Result<()> {
    // invalid sha256: made of 63 chars
    let invalid_sha256 = "735e3ec1b05d901d07e84b1504518442aba2395fe3f945a1c962e81a8e152b2";

    assert!(Checksum::parse(invalid_sha256).is_err());

    // invalid sha256: made of 65 chars
    let invalid_sha256 = "735e3ec1b05d901d07e84b1504518442aba2395fe3f945a1c962e81a8e152b2da";

    assert!(Checksum::parse(invalid_sha256).is_err());
    Ok(())
}

#[tokio::test]
async fn test_parse_sha_256_from_valid_string_should_work() -> std::io::Result<()> {
    // invalid sha256: made of 63 chars
    let valid_sha256 = "735e3ec1b05d901d07e84b1504518442aba2395fe3f945a1c962e81a8e152b2z";

    assert!(Checksum::parse(valid_sha256).is_ok());
    Ok(())
}
