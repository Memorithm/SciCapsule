//! Safe materialization of integrity-verified SciRust capsules.
//!
//! The canonical container represents payloads as bytes only. This module
//! therefore creates directories and regular files only; it never restores
//! symlinks, device nodes, sockets, ownership, or producer-supplied modes.

use scirust_capsule::Capsule;
use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Maximum manifest/header allowance accepted by the extraction CLI in
/// addition to the configured payload-byte limit.
pub const MAX_CAPSULE_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// Conservative default extraction limits. Callers can choose lower limits.
pub const DEFAULT_EXTRACTION_LIMITS: ExtractionLimits = ExtractionLimits {
    max_files: 4_096,
    max_total_bytes: 1024 * 1024 * 1024,
};

/// Resource limits applied before materialization starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtractionLimits {
    pub max_files: usize,
    pub max_total_bytes: u64,
}

/// Description of a completed materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtractionSummary {
    pub destination: PathBuf,
    pub entrypoint: PathBuf,
    pub file_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug)]
pub enum ExtractionError {
    TooManyFiles {
        actual: usize,
        limit: usize,
    },
    TooManyBytes {
        actual: u64,
        limit: u64,
    },
    SizeOverflow,
    InvalidPath {
        path: String,
        reason: &'static str,
    },
    DuplicatePath(String),
    ConflictingPaths {
        file: String,
        descendant: String,
    },
    InvalidDestination(String),
    DestinationExists(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyFiles { actual, limit } => {
                write!(
                    f,
                    "capsule contains {actual} files; extraction limit is {limit}"
                )
            }
            Self::TooManyBytes { actual, limit } => write!(
                f,
                "capsule contains {actual} payload bytes; extraction limit is {limit}"
            ),
            Self::SizeOverflow => f.write_str("capsule payload-byte total overflows u64"),
            Self::InvalidPath { path, reason } => {
                write!(f, "payload path {path:?} cannot be materialized: {reason}")
            }
            Self::DuplicatePath(path) => write!(f, "duplicate payload path {path:?}"),
            Self::ConflictingPaths { file, descendant } => write!(
                f,
                "payload path conflict: file {file:?} is an ancestor of {descendant:?}"
            ),
            Self::InvalidDestination(reason) => {
                write!(f, "invalid extraction destination: {reason}")
            }
            Self::DestinationExists(path) => write!(
                f,
                "extraction destination {} already exists; refusing to merge or overwrite",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(f, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ExtractionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Materialize an already integrity-verified capsule into a new directory.
///
/// [`Capsule`] can only be obtained through validated construction or a full
/// canonical decode. The complete path/resource preflight happens before a
/// private staging directory is created. The final destination must not exist.
pub fn extract_capsule(
    capsule: &Capsule,
    destination: &Path,
    limits: ExtractionLimits,
) -> Result<ExtractionSummary, ExtractionError> {
    let preflight = preflight(capsule, limits)?;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if destination.file_name().is_none() {
        return Err(ExtractionError::InvalidDestination(
            "a named directory is required".to_owned(),
        ));
    }
    reject_existing_destination(destination)?;

    let staging = tempfile::Builder::new()
        .prefix(".scicapsule-staging-")
        .tempdir_in(parent)
        .map_err(|source| io_error("create staging directory in", parent, source))?;

    for payload in capsule.payloads() {
        let relative = portable_path(payload.path().as_str())?;
        let target = staging.path().join(relative);
        let target_parent = target
            .parent()
            .ok_or_else(|| ExtractionError::InvalidPath {
                path: payload.path().to_string(),
                reason: "path has no parent",
            })?;
        fs::create_dir_all(target_parent)
            .map_err(|source| io_error("create directory", target_parent, source))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|source| io_error("create regular file", &target, source))?;
        file.write_all(payload.bytes())
            .map_err(|source| io_error("write regular file", &target, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync regular file", &target, source))?;
    }

    reject_existing_destination(destination)?;
    rename_no_replace(staging.path(), destination)
        .map_err(|source| io_error("publish extracted directory at", destination, source))?;

    Ok(ExtractionSummary {
        destination: destination.to_path_buf(),
        entrypoint: destination.join(portable_path(capsule.manifest().entrypoint().as_str())?),
        file_count: preflight.file_count,
        total_bytes: preflight.total_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Preflight {
    file_count: usize,
    total_bytes: u64,
}

fn preflight(capsule: &Capsule, limits: ExtractionLimits) -> Result<Preflight, ExtractionError> {
    let file_count = capsule.payloads().len();
    if file_count > limits.max_files {
        return Err(ExtractionError::TooManyFiles {
            actual: file_count,
            limit: limits.max_files,
        });
    }

    let mut total_bytes = 0_u64;
    let mut paths = BTreeSet::new();
    for payload in capsule.payloads() {
        portable_path(payload.path().as_str())?;
        total_bytes = total_bytes
            .checked_add(
                u64::try_from(payload.bytes().len()).map_err(|_| ExtractionError::SizeOverflow)?,
            )
            .ok_or(ExtractionError::SizeOverflow)?;
        if !paths.insert(payload.path().as_str()) {
            return Err(ExtractionError::DuplicatePath(payload.path().to_string()));
        }
    }
    if total_bytes > limits.max_total_bytes {
        return Err(ExtractionError::TooManyBytes {
            actual: total_bytes,
            limit: limits.max_total_bytes,
        });
    }

    for path in &paths {
        let mut prefix = String::new();
        let components: Vec<_> = path.split('/').collect();
        for component in &components[..components.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if paths.contains(prefix.as_str()) {
                return Err(ExtractionError::ConflictingPaths {
                    file: prefix,
                    descendant: (*path).to_owned(),
                });
            }
        }
    }

    Ok(Preflight {
        file_count,
        total_bytes,
    })
}

fn portable_path(path: &str) -> Result<PathBuf, ExtractionError> {
    if path.is_empty() || path.starts_with('/') {
        return Err(ExtractionError::InvalidPath {
            path: path.to_owned(),
            reason: "path must be non-empty and relative",
        });
    }

    let mut relative = PathBuf::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ExtractionError::InvalidPath {
                path: path.to_owned(),
                reason: "empty, current-directory, or parent-directory component",
            });
        }
        if component.contains(['\\', ':', '\0']) {
            return Err(ExtractionError::InvalidPath {
                path: path.to_owned(),
                reason: "non-portable path syntax",
            });
        }
        relative.push(component);
    }
    Ok(relative)
}

fn reject_existing_destination(destination: &Path) -> Result<(), ExtractionError> {
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(ExtractionError::DestinationExists(
            destination.to_path_buf(),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(
            "inspect extraction destination",
            destination,
            source,
        )),
    }
}

#[cfg(unix)]
fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        source,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(not(unix))]
fn rename_no_replace(_source: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory publication is not implemented on this platform",
    ))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ExtractionError {
    ExtractionError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scirust_capsule::CapsulePayload;
    use scirust_capsule_schema::CapsulePath;

    fn path(value: &str) -> CapsulePath {
        CapsulePath::new(value).unwrap()
    }

    fn capsule(payloads: Vec<(&str, &[u8])>, entrypoint: &str) -> Capsule {
        Capsule::new(
            "test",
            path(entrypoint),
            payloads
                .into_iter()
                .map(|(name, bytes)| CapsulePayload::new(path(name), bytes.to_vec()))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn preserves_payload_bytes_exactly() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("output");
        let bytes = [0, 1, 2, 0xff, b'\n'];
        let value = capsule(vec![("bin/run", &bytes), ("data/empty", b"")], "bin/run");

        let summary = extract_capsule(&value, &destination, DEFAULT_EXTRACTION_LIMITS).unwrap();

        assert_eq!(fs::read(destination.join("bin/run")).unwrap(), bytes);
        assert_eq!(fs::read(destination.join("data/empty")).unwrap(), b"");
        assert_eq!(summary.file_count, 2);
        assert_eq!(summary.total_bytes, bytes.len() as u64);
        assert_eq!(summary.entrypoint, destination.join("bin/run"));
    }

    #[test]
    fn rejects_file_directory_conflicts_before_writing() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("output");
        let value = capsule(vec![("bin", b"file"), ("bin/run", b"child")], "bin");

        let error = extract_capsule(&value, &destination, DEFAULT_EXTRACTION_LIMITS).unwrap_err();

        assert!(matches!(error, ExtractionError::ConflictingPaths { .. }));
        assert!(!destination.exists());
    }

    #[test]
    fn enforces_file_and_byte_limits_before_writing() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("output");
        let value = capsule(vec![("bin/run", b"1234")], "bin/run");

        let file_error = extract_capsule(
            &value,
            &destination,
            ExtractionLimits {
                max_files: 0,
                max_total_bytes: 4,
            },
        )
        .unwrap_err();
        assert!(matches!(file_error, ExtractionError::TooManyFiles { .. }));

        let byte_error = extract_capsule(
            &value,
            &destination,
            ExtractionLimits {
                max_files: 1,
                max_total_bytes: 3,
            },
        )
        .unwrap_err();
        assert!(matches!(byte_error, ExtractionError::TooManyBytes { .. }));
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_existing_symlink_destination() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let outside = parent.path().join("outside");
        let destination = parent.path().join("output");
        fs::create_dir(&outside).unwrap();
        symlink(&outside, &destination).unwrap();
        let value = capsule(vec![("bin/run", b"payload")], "bin/run");

        let error = extract_capsule(&value, &destination, DEFAULT_EXTRACTION_LIMITS).unwrap_err();

        assert!(matches!(error, ExtractionError::DestinationExists(_)));
        assert!(!outside.join("bin/run").exists());
    }

    #[test]
    fn canonical_path_type_rejects_absolute_and_traversal_paths() {
        for invalid in ["/bin/run", "../bin/run", "bin/../run"] {
            assert!(CapsulePath::new(invalid).is_err());
        }
    }

    #[test]
    fn canonical_capsule_construction_rejects_duplicate_paths() {
        let duplicate = Capsule::new(
            "test",
            path("bin/run"),
            vec![
                CapsulePayload::new(path("bin/run"), b"first".to_vec()),
                CapsulePayload::new(path("bin/run"), b"second".to_vec()),
            ],
        )
        .unwrap_err();

        assert!(duplicate.to_string().contains("duplicate"));
    }

    #[test]
    fn existing_regular_destination_is_never_overwritten() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("output");
        fs::write(&destination, b"keep me").unwrap();
        let value = capsule(vec![("bin/run", b"payload")], "bin/run");

        let error = extract_capsule(&value, &destination, DEFAULT_EXTRACTION_LIMITS).unwrap_err();

        assert!(matches!(error, ExtractionError::DestinationExists(_)));
        assert_eq!(fs::read(destination).unwrap(), b"keep me");
    }
}
