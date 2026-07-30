#![cfg(all(feature = "m0-test-profile", unix))]

use secure_onboard::m0_secure_fs::{
    create_private_file, create_private_subdirectory, require_private_directory,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

#[test]
fn m0_state_and_evidence_storage_require_private_owner_only_modes() {
    let root = tempfile::tempdir().expect("temp root");
    let physical_root = root.path().canonicalize().expect("physical temp root");
    let path = physical_root.join("private");
    fs::create_dir(&path).expect("create directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("set public mode");
    assert!(require_private_directory(&path).is_err());

    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("set private mode");
    require_private_directory(&path).expect("private directory");

    let child = create_private_subdirectory(&path, "events").expect("private subdirectory");
    assert_eq!(fs::metadata(&child).unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&child).unwrap().uid(), unsafe {
        libc::geteuid()
    });

    let file = child.join("evidence.bin");
    create_private_file(&file, b"synthetic").expect("private file");
    assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&file).unwrap().uid(), unsafe {
        libc::geteuid()
    });
}

#[test]
fn private_storage_rejects_a_symlink_in_any_existing_path_component() {
    let root = tempfile::tempdir().expect("temp root");
    let physical_root = root.path().canonicalize().expect("physical temp root");
    let physical = physical_root.join("physical");
    let private = physical.join("private");
    fs::create_dir_all(&private).expect("create private directory");
    fs::set_permissions(&physical, fs::Permissions::from_mode(0o700))
        .expect("set physical parent mode");
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))
        .expect("set private directory mode");

    let alias = physical_root.join("alias");
    symlink(&physical, &alias).expect("create ancestor symlink");

    assert!(require_private_directory(&alias.join("private")).is_err());
}
