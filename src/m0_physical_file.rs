use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const HASH_CHUNK_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhysicalFileError {
    PathInvalid,
    SizeLimitExceeded,
    DigestMismatch,
}

pub(crate) struct PhysicalFileContents {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
struct PhysicalFileMetadata {
    length: u64,
    readonly: bool,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    user: u32,
    #[cfg(unix)]
    group: u32,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    created: u64,
    #[cfg(windows)]
    last_written: u64,
    #[cfg(not(any(unix, windows)))]
    modified: Option<std::time::SystemTime>,
}

impl PhysicalFileMetadata {
    fn capture(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        #[cfg(windows)]
        use std::os::windows::fs::MetadataExt;

        Self {
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(unix)]
            links: metadata.nlink(),
            #[cfg(unix)]
            user: metadata.uid(),
            #[cfg(unix)]
            group: metadata.gid(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
            #[cfg(windows)]
            attributes: metadata.file_attributes(),
            #[cfg(windows)]
            created: metadata.creation_time(),
            #[cfg(windows)]
            last_written: metadata.last_write_time(),
            #[cfg(not(any(unix, windows)))]
            modified: metadata.modified().ok(),
        }
    }
}

struct OpenedPhysicalFile {
    path: PathBuf,
    file: fs::File,
    initial_metadata: PhysicalFileMetadata,
}

impl OpenedPhysicalFile {
    fn open(path: &Path) -> Result<Self, PhysicalFileError> {
        if !path.is_absolute() {
            return Err(PhysicalFileError::PathInvalid);
        }
        let physical = fs::canonicalize(path).map_err(|_| PhysicalFileError::PathInvalid)?;
        let path_metadata =
            fs::symlink_metadata(path).map_err(|_| PhysicalFileError::PathInvalid)?;
        if physical != path || !path_metadata.file_type().is_file() {
            return Err(PhysicalFileError::PathInvalid);
        }

        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(&physical)
            .map_err(|_| PhysicalFileError::PathInvalid)?;
        let descriptor_metadata = file
            .metadata()
            .map_err(|_| PhysicalFileError::PathInvalid)?;
        let path_metadata =
            fs::symlink_metadata(&physical).map_err(|_| PhysicalFileError::PathInvalid)?;
        let initial_metadata = PhysicalFileMetadata::capture(&descriptor_metadata);
        if !descriptor_metadata.file_type().is_file()
            || !path_metadata.file_type().is_file()
            || initial_metadata != PhysicalFileMetadata::capture(&path_metadata)
        {
            return Err(PhysicalFileError::PathInvalid);
        }
        Ok(Self {
            path: physical,
            file,
            initial_metadata,
        })
    }

    fn inspect(
        mut self,
        max_bytes: u64,
        capture_bytes: bool,
    ) -> Result<PhysicalFileObservation, PhysicalFileError> {
        if self.initial_metadata.length > max_bytes {
            return Err(PhysicalFileError::SizeLimitExceeded);
        }
        let observation = stream_sha256(&mut self.file, max_bytes, capture_bytes.then(Vec::new))?;
        self.validate_unchanged()?;
        Ok(observation)
    }

    fn validate_unchanged(&self) -> Result<(), PhysicalFileError> {
        let descriptor_metadata = self
            .file
            .metadata()
            .map_err(|_| PhysicalFileError::PathInvalid)?;
        let path_metadata =
            fs::symlink_metadata(&self.path).map_err(|_| PhysicalFileError::PathInvalid)?;
        let canonical = fs::canonicalize(&self.path).map_err(|_| PhysicalFileError::PathInvalid)?;
        if !descriptor_metadata.file_type().is_file()
            || !path_metadata.file_type().is_file()
            || canonical != self.path
            || PhysicalFileMetadata::capture(&descriptor_metadata) != self.initial_metadata
            || PhysicalFileMetadata::capture(&path_metadata) != self.initial_metadata
        {
            return Err(PhysicalFileError::PathInvalid);
        }
        Ok(())
    }
}

pub(crate) fn validate_digest(path: &Path, expected_digest: &str) -> Result<(), PhysicalFileError> {
    validate_digest_bounded(path, expected_digest, DEFAULT_MAX_FILE_BYTES)
}

pub(crate) fn validate_digest_bounded(
    path: &Path,
    expected_digest: &str,
    max_bytes: u64,
) -> Result<(), PhysicalFileError> {
    if OpenedPhysicalFile::open(path)?
        .inspect(max_bytes, false)?
        .sha256
        != expected_digest
    {
        return Err(PhysicalFileError::DigestMismatch);
    }
    Ok(())
}

pub(crate) fn read_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<PhysicalFileContents, PhysicalFileError> {
    let observation = OpenedPhysicalFile::open(path)?.inspect(max_bytes, true)?;
    Ok(PhysicalFileContents {
        bytes: observation.bytes.expect("capture requested"),
        sha256: observation.sha256,
    })
}

#[derive(Debug, Eq, PartialEq)]
struct PhysicalFileObservation {
    bytes: Option<Vec<u8>>,
    sha256: String,
}

fn stream_sha256(
    mut reader: impl Read,
    max_bytes: u64,
    mut bytes: Option<Vec<u8>>,
) -> Result<PhysicalFileObservation, PhysicalFileError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; HASH_CHUNK_BYTES];
    let mut total_bytes = 0_u64;
    loop {
        let length = reader
            .read(&mut buffer)
            .map_err(|_| PhysicalFileError::PathInvalid)?;
        if length == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(length as u64)
            .ok_or(PhysicalFileError::SizeLimitExceeded)?;
        if total_bytes > max_bytes {
            return Err(PhysicalFileError::SizeLimitExceeded);
        }
        digest.update(&buffer[..length]);
        if let Some(bytes) = &mut bytes {
            bytes.extend_from_slice(&buffer[..length]);
        }
    }
    Ok(PhysicalFileObservation {
        bytes,
        sha256: format!("sha256:{}", hex::encode(digest.finalize())),
    })
}

#[cfg(test)]
mod tests {
    use super::{HASH_CHUNK_BYTES, OpenedPhysicalFile, PhysicalFileError, stream_sha256};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{self, Read};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct BoundedReader {
        remaining: usize,
    }

    impl Read for BoundedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(
                buffer.len() <= HASH_CHUNK_BYTES,
                "hash reader requested an unbounded buffer"
            );
            let length = self.remaining.min(buffer.len());
            buffer[..length].fill(b'x');
            self.remaining -= length;
            Ok(length)
        }
    }

    #[test]
    fn streaming_digest_reads_large_inputs_in_bounded_chunks() {
        let size = HASH_CHUNK_BYTES * 5 + 17;
        let mut expected = Sha256::new();
        for _ in 0..size {
            expected.update(b"x");
        }

        let actual = stream_sha256(BoundedReader { remaining: size }, size as u64, None)
            .expect("streaming digest succeeds")
            .sha256;

        assert_eq!(
            actual,
            format!("sha256:{}", hex::encode(expected.finalize()))
        );
    }

    #[test]
    fn streaming_digest_stops_at_the_declared_total_byte_limit() {
        assert_eq!(
            stream_sha256(BoundedReader { remaining: 5 }, 4, Some(Vec::new())),
            Err(PhysicalFileError::SizeLimitExceeded)
        );
    }

    #[cfg(unix)]
    #[test]
    fn opened_file_digest_rejects_metadata_changes_during_validation() {
        let root = tempfile::tempdir().expect("temporary root");
        let path = root
            .path()
            .canonicalize()
            .expect("physical temporary root")
            .join("artifact");
        fs::write(&path, b"bound artifact").expect("write artifact");
        let opened = OpenedPhysicalFile::open(&path).expect("open physical artifact");

        let mut permissions = fs::metadata(&path)
            .expect("artifact metadata")
            .permissions();
        permissions.set_mode(0o400);
        fs::set_permissions(&path, permissions).expect("change artifact metadata");

        assert_eq!(
            opened.inspect(u64::MAX, false),
            Err(PhysicalFileError::PathInvalid)
        );
    }
}
