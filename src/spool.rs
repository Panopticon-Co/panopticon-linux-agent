use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// One atomically-written JSON record per segment. Delivery deletes only acknowledged files.
pub struct SegmentSpool {
    dir: PathBuf,
    quota_bytes: u64,
}
impl SegmentSpool {
    pub fn open(dir: impl AsRef<Path>, quota_bytes: u64) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        Ok(Self {
            dir: dir.as_ref().to_path_buf(),
            quota_bytes,
        })
    }
    pub fn append(&self, payload: &[u8]) -> io::Result<PathBuf> {
        if payload.len() as u64 > self.quota_bytes
            || self.size()? + payload.len() as u64 > self.quota_bytes
        {
            return Err(io::Error::other("spool quota exceeded"));
        }
        let name = format!("{:x}.ndjson", Sha256::digest(payload));
        let final_path = self.dir.join(name);
        if final_path.exists() {
            return Ok(final_path);
        }
        let tmp = final_path.with_extension("tmp");
        fs::write(&tmp, payload)?;
        fs::rename(&tmp, &final_path)?;
        Ok(final_path)
    }
    pub fn pending(&self) -> io::Result<Vec<PathBuf>> {
        let mut p: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
            .collect();
        p.sort();
        Ok(p)
    }
    pub fn acknowledge(&self, path: &Path) -> io::Result<()> {
        if path.parent() != Some(self.dir.as_path()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "foreign spool path",
            ));
        }
        fs::remove_file(path)
    }
    pub fn size(&self) -> io::Result<u64> {
        Ok(fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum())
    }
}
