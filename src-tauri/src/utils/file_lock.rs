//! Cross-platform non-blocking exclusive file lock.
//!
//! `std::fs::File::try_lock` is *unsupported* on Android (std only implements it for
//! `target_os = "linux"` and a few others, not `"android"`): it returns an opaque I/O error, which
//! made every settings save fail on the phone ("lock acquisition failed due to I/O error").
//! `fs2` uses `flock(2)` directly and works on Android, Linux, macOS and Windows.

use std::fs::File;
use std::io::ErrorKind;

#[derive(Debug)]
pub enum FileLockError {
    /// Another holder has the lock.
    WouldBlock,
    Error(std::io::Error),
}

impl std::fmt::Display for FileLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLockError::WouldBlock => write!(f, "file is locked by another holder"),
            FileLockError::Error(error) => write!(f, "file lock failed: {error}"),
        }
    }
}

/// Try to take an exclusive lock without blocking. The lock is released when `file` is dropped.
pub fn try_lock_exclusive(file: &File) -> Result<(), FileLockError> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error) => {
            let contended = fs2::lock_contended_error();
            if error.kind() == ErrorKind::WouldBlock
                || (error.raw_os_error().is_some()
                    && error.raw_os_error() == contended.raw_os_error())
            {
                Err(FileLockError::WouldBlock)
            } else {
                Err(FileLockError::Error(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_exclusive_lock_on_same_file_would_block_then_succeeds_after_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lock");
        let a = std::fs::OpenOptions::new().read(true).write(true).create(true).open(&path).unwrap();
        let b = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        try_lock_exclusive(&a).expect("first lock");
        assert!(matches!(try_lock_exclusive(&b), Err(FileLockError::WouldBlock)));
        drop(a);
        try_lock_exclusive(&b).expect("lock after release");
    }
}
