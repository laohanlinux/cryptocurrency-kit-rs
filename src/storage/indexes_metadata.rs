#[allow(unsafe_code)]
use serde_json::{self, Error as JsonError};

use std::io::Cursor;
use std::{borrow::Cow, error::Error, fmt};

use super::db::{Fork, Snapshot};
#[macro_use]
use super::values::{self, StorageValue};
use super::base_index::BaseIndex;

use crypto::{self, hash, CryptoHash, Hash};
use encoding::msgpack;

use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize}; // use in Derive

pub const INDEXES_METADATA_TABLE_NAME: &str = "__INDEXES_METADATA__";

// Storage metadata of a current Exonum version.
// Value of this constant is to be changed manually
// upon the introduction of breaking changes to the storage.
 const CORE_STORAGE_METADATA: StorageMetadata = StorageMetadata { version: 0 };
const CORE_STORAGE_METADATA_KEY: &str = "__STORAGE_METADATA__";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct IndexMetadata {
    //    index_type: IndexType,
    is_family: bool,
}

//implement_storagevalue_traits! {IndexMetadata}

impl StorageValue for IndexMetadata {
    fn into_bytes(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        buf
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let cur = Cursor::new(&value);
        let mut de = Deserializer::new(cur);
        let actual: IndexMetadata = Deserialize::deserialize(&mut de).unwrap();
        actual
    }
}

implement_cryptohash_traits! {IndexMetadata}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum IndexType {
    Entry,
    KeySet,
    List,
    SparseList,
    Map,
    ProofList,
    ProofMap,
    ValueSet,
}

impl From<u8> for IndexType {
    fn from(num: u8) -> Self {
        use self::IndexType::*;
        match num {
            0 => Entry,
            1 => KeySet,
            2 => List,
            3 => SparseList,
            4 => Map,
            5 => ProofList,
            6 => ProofMap,
            7 => ValueSet,
            invalid => panic!(
                "Unreachable pattern ({:?}) while constructing table type. \
                 Storage data is probably corrupted",
                invalid
            ),
        }
    }
}

implement_cryptohash_traits! {IndexType}

impl StorageValue for IndexType {
    fn into_bytes(self) -> Vec<u8> {
        (self as u8).into_bytes()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        <u8 as StorageValue>::from_bytes(value).into()
    }
}

pub fn assert_index_type(name: &str, index_type: IndexType, is_family: bool, view: &dyn Snapshot) {
    let metadata = BaseIndex::indexes_metadata(view);
    if let Some(value) = metadata.get::<_, IndexMetadata>(name) {
        let stored_type = value.index_type();
        let stored_is_family = value.is_family();
        assert_eq!(
            stored_type, index_type,
            "Attempt to access index '{}' of type {:?}, \
             while said index was initially created with type {:?}",
            name, index_type, stored_type
        );
        assert_eq!(
            stored_is_family,
            is_family,
            "Attempt to access {} '{}' while it's {}",
            if is_family {
                "index family"
            } else {
                "an ordinary index"
            },
            name,
            if stored_is_family {
                "index family "
            } else {
                "an ordinary index"
            }
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StorageMetadata {
    version: u32,
}

impl StorageMetadata {
    pub fn current() -> Self {CORE_STORAGE_METADATA}

    pub fn try_serialize(&self) -> Result<Vec<u8>, JsonError> {serde_json::to_vec(&self)}

    pub fn try_deserialize(serialized: &[u8]) -> Result<Self, JsonError> { serde_json::from_slice(serialized) }

    pub fn write_current(view: &mut Fork) {
        let mut metadata = BaseIndex::indexes_metadata(view);
        metadata.put(&CORE_STORAGE_METADATA_KEY.to_owned(), Self::current());
    }

    pub fn read<T: AsRef<dyn Snapshot>>(view: T) -> Result<Self, super::Error> {
        let metadata = BaseIndex::indexes_metadata(view);
        match metadata.get::<_, Self>(CORE_STORAGE_METADATA_KEY) {
            Some(ref ver) if *ver == CORE_STORAGE_METADATA => Ok(ver.clone()),
            Some(ref ver) => Err(super::Error::new(format!(
                "Unsupported storage version: [{}]. Current storage version: [{}].",
                ver,
                StorageMetadata::current(),
            ))),
            None => Err(super::Error::new(format!(
                "Storage version is not specified. Current storage version: [{}].",
                StorageMetadata::current()
            ))),
        }
    }
}

implement_cryptohash_traits! {StorageMetadata}

impl StorageValue for StorageMetadata {
    fn into_bytes(self) -> Vec<u8> {
        self.try_serialize().unwrap()
    }

    fn from_bytes(v: ::std::borrow::Cow<[u8]>) -> Self {
        StorageMetadata::try_deserialize(v.as_ref()).unwrap()
    }
}

impl fmt::Display for StorageMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.version)
    }
}

pub fn set_index_type(name: &str, index_type: IndexType, is_family: bool, view: &mut Fork) {
    if name == INDEXES_METADATA_TABLE_NAME || name == CORE_STORAGE_METADATA_KEY {
        panic!("Attempt to access an internal storage infrastructure");
    }
    let mut metadata = BaseIndex::indexes_metadata(view);
    if metadata.get::<_, IndexMetadata>(name).is_none() {
        metadata.put(&name.to_owned(), IndexMetadata::new(index_type, is_family));
    }
}

