#![cfg(feature = "m0-test-profile")]

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

#[derive(Debug, Error)]
pub enum PrivateFsError {
    #[error("private M0 path is invalid")]
    InvalidPath,
    #[error("private M0 storage I/O failed")]
    Io,
}

pub fn require_private_directory(path: &Path) -> Result<(), PrivateFsError> {
    require_physical_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| PrivateFsError::Io)?;
    if !metadata.is_dir() {
        return Err(PrivateFsError::InvalidPath);
    }
    #[cfg(unix)]
    if metadata.uid() != current_uid() || metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(PrivateFsError::InvalidPath);
    }
    Ok(())
}

pub fn create_private_subdirectory(parent: &Path, name: &str) -> Result<PathBuf, PrivateFsError> {
    require_private_directory(parent)?;
    if name.is_empty()
        || Path::new(name)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(PrivateFsError::InvalidPath);
    }
    let path = parent.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => require_private_directory(&path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(&path).map_err(|_| PrivateFsError::Io)?;
            require_private_directory(&path)?;
        }
        Err(_) => return Err(PrivateFsError::Io),
    }
    Ok(path)
}

pub fn create_private_file(path: &Path, bytes: &[u8]) -> Result<(), PrivateFsError> {
    let parent = path.parent().ok_or(PrivateFsError::InvalidPath)?;
    require_private_directory(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|_| PrivateFsError::Io)?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(PrivateFsError::Io);
    }
    require_private_file(path)
}

pub fn require_private_file(path: &Path) -> Result<(), PrivateFsError> {
    require_physical_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| PrivateFsError::Io)?;
    if !metadata.is_file() {
        return Err(PrivateFsError::InvalidPath);
    }
    #[cfg(unix)]
    if metadata.uid() != current_uid() || metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(PrivateFsError::InvalidPath);
    }
    Ok(())
}

fn require_physical_path(path: &Path) -> Result<(), PrivateFsError> {
    if !path.is_absolute() {
        return Err(PrivateFsError::InvalidPath);
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            Component::CurDir | Component::ParentDir => return Err(PrivateFsError::InvalidPath),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| PrivateFsError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(PrivateFsError::InvalidPath);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}
