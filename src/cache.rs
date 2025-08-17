use crate::parser::parse_classnames;
use bincode::{
    Decode, Encode,
    config::standard,
    error::{DecodeError, EncodeError},
};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub enum CacheError {
    Sled(sled::Error),
    Io(std::io::Error),
    Encode(EncodeError),
    Decode(DecodeError),
    Time(std::time::SystemTimeError),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheError::Sled(e) => write!(f, "Database error: {}", e),
            CacheError::Io(e) => write!(f, "IO error: {}", e),
            CacheError::Encode(e) => write!(f, "Encoding error: {}", e),
            CacheError::Decode(e) => write!(f, "Decoding error: {}", e),
            CacheError::Time(e) => write!(f, "System time error: {}", e),
        }
    }
}

impl Error for CacheError {}
impl From<sled::Error> for CacheError {
    fn from(e: sled::Error) -> Self {
        CacheError::Sled(e)
    }
}
impl From<std::io::Error> for CacheError {
    fn from(e: std::io::Error) -> Self {
        CacheError::Io(e)
    }
}
impl From<EncodeError> for CacheError {
    fn from(e: EncodeError) -> Self {
        CacheError::Encode(e)
    }
}
impl From<DecodeError> for CacheError {
    fn from(e: DecodeError) -> Self {
        CacheError::Decode(e)
    }
}
impl From<std::time::SystemTimeError> for CacheError {
    fn from(e: std::time::SystemTimeError) -> Self {
        CacheError::Time(e)
    }
}

#[derive(Clone, Serialize, Deserialize, Encode, Decode)]
pub struct FileCache {
    pub modified: u64,
    pub classnames: HashSet<String>,
}

pub struct ClassnameCache {
    db: Db,
}

impl ClassnameCache {
    pub fn new(db_path: &str) -> Result<Self, sled::Error> {
        let db = sled::open(db_path)?;
        Ok(Self { db })
    }

    #[allow(dead_code)]
    pub fn get(&self, path: &Path) -> Result<Option<HashSet<String>>, CacheError> {
        let path_key = path.to_string_lossy();
        let Some(data) = self.db.get(path_key.as_bytes())? else {
            return Ok(None);
        };
        let (cached, _): (FileCache, usize) = bincode::decode_from_slice(&data, standard())?;
        let modified = fs::metadata(path)?
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        if cached.modified == modified {
            Ok(Some(cached.classnames))
        } else {
            Ok(None)
        }
    }

    #[allow(dead_code)]
    pub fn set(&self, path: &Path, classnames: &HashSet<String>) -> Result<(), CacheError> {
        let path_key = path.to_string_lossy();
        let modified = if path.exists() {
            fs::metadata(path)?
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        } else {
            0
        };

        let file_cache = FileCache {
            modified,
            classnames: classnames.clone(),
        };

        let encoded = bincode::encode_to_vec(&file_cache, standard())?;
        self.db.insert(path_key.as_bytes(), encoded)?;
        Ok(())
    }

    pub fn remove(&self, path: &Path) -> Result<(), CacheError> {
        let path_key = path.to_string_lossy();
        self.db.remove(path_key.as_bytes())?;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (PathBuf, FileCache)> {
        self.db.iter().filter_map(|item| {
            let (key, value) = item.ok()?;
            let path = PathBuf::from(String::from_utf8_lossy(&key).to_string());
            let file_cache: Result<(FileCache, usize), _> =
                bincode::decode_from_slice(&value, standard());
            file_cache.ok().map(|(fc, _)| (path, fc))
        })
    }

    #[allow(dead_code)]
    pub fn compare_and_generate(&self, path: &Path) -> Result<Option<HashSet<String>>, CacheError> {
        if self.get(path)?.is_some() {
            return Ok(None);
        }

        let current_classnames = parse_classnames(path);
        self.set(path, &current_classnames)?;
        Ok(Some(current_classnames))
    }
}
