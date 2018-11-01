// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A definition of `StorageValue` trait and implementations for common types.

use byteorder::{ByteOrder, LittleEndian};
use chrono::prelude::*;
use chrono::{DateTime, NaiveDateTime, Utc};
use encoding;
use rmps::decode::Error;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::borrow::Cow;
use std::io::Cursor;
use std::mem;

use super::hash::UniqueHash;
use types::Zero;
use crypto::{CryptoHash, Hash};
use ethkey::Public as PublicKey;

/// A type that can be (de)serialized as a value in the blockchain storage.
///
/// `StorageValue` is automatically implemented by the [`encoding_struct!`] and [`transactions!`]
/// macros. In case you need to implement it manually, use little-endian encoding
/// for integer types for compatibility with modern architectures.
///
/// # Examples
///
/// Implementing `StorageValue` for the type:
///
/// ```
/// # extern crate exonum;
/// # extern crate byteorder;
/// use std::borrow::Cow;
/// use exonum::storage::StorageValue;
/// use exonum::crypto::{self, CryptoHash, Hash};
/// use byteorder::{LittleEndian, ByteOrder};
///
/// struct Data {
///     a: i16,
///     b: u32,
/// }
///
/// impl CryptoHash for Data {
///     fn hash(&self) -> Hash {
///         let mut buffer = [0; 6];
///         LittleEndian::write_i16(&mut buffer[0..2], self.a);
///         LittleEndian::write_u32(&mut buffer[2..6], self.b);
///         crypto::hash(&buffer)
///     }
/// }
///
/// impl StorageValue for Data {
///     fn into_bytes(self) -> Vec<u8> {
///         let mut buffer = vec![0; 6];
///         LittleEndian::write_i16(&mut buffer[0..2], self.a);
///         LittleEndian::write_u32(&mut buffer[2..6], self.b);
///         buffer
///     }
///
///     fn from_bytes(value: Cow<[u8]>) -> Self {
///         let a = LittleEndian::read_i16(&value[0..2]);
///         let b = LittleEndian::read_u32(&value[2..6]);
///         Data { a, b }
///     }
/// }
/// # fn main() {}
/// ```
///
/// [`encoding_struct!`]: ../macro.encoding_struct.html
/// [`transactions!`]: ../macro.transactions.html
pub trait StorageValue: UniqueHash + Sized {
    /// Serialize a value into a vector of bytes.
    fn into_bytes(self) -> Vec<u8>;

    /// Deserialize a value from bytes.
    fn from_bytes(value: Cow<[u8]>) -> Self;
}

#[macro_export]
macro_rules! implement_storagevalue_traits {
    ($key: ident) => {
        impl StorageValue for $key {
            fn into_bytes(self) -> Vec<u8> {
                let mut buf: Vec<u8> = Vec::new();
                self.serialize(&mut Serializer::new(&mut buf)).unwrap();
                buf
            }
            fn from_bytes(value: Cow<[u8]>) -> Self {
                let cur = Cursor::new(&value[..]);
                let mut de = Deserializer::new(cur);
                Deserialize::deserialize(&mut de).unwrap()
            }
        }
    };
}

implement_storagevalue_traits! {bool}
implement_storagevalue_traits! {u8}
implement_storagevalue_traits! {u16}
implement_storagevalue_traits! {u32}
implement_storagevalue_traits! {u64}
implement_storagevalue_traits! {i8}
implement_storagevalue_traits! {i16}
implement_storagevalue_traits! {i32}
implement_storagevalue_traits! {i64}
/// Uses UTF-8 string serialization.
implement_storagevalue_traits! {String}
implement_storagevalue_traits! {Uuid}

/// No-op implementation.
impl StorageValue for () {
    fn into_bytes(self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        buf
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let cur = Cursor::new(&value[..]);
        let mut de = Deserializer::new(cur);
        Deserialize::deserialize(&mut de).unwrap()
    }
}

impl StorageValue for Zero {
    fn into_bytes(self) -> Vec<u8> {
        vec![]
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        Zero
    }
}

// Hash is very special
impl StorageValue for Hash {
    fn into_bytes(self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.as_ref()
            .to_vec()
            .serialize(&mut Serializer::new(&mut buf))
            .unwrap();
        buf
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let cur = Cursor::new(&value[..]);
        let mut de = Deserializer::new(cur);
        let v: Vec<u8> = Deserialize::deserialize(&mut de).unwrap();
        Hash::new(&v)
    }
}

impl StorageValue for PublicKey {
    fn into_bytes(self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.0
            .as_ref()
            .serialize(&mut Serializer::new(&mut buf))
            .unwrap();
        buf
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let cur = Cursor::new(&value[..]);
        let mut de = Deserializer::new(cur);
        let v: Vec<u8> = Deserialize::deserialize(&mut de).unwrap();
        PublicKey::from_slice(&v)
    }
}

//impl StorageValue for RawMessage {
//    fn into_bytes(self) -> Vec<u8> {
//        self.as_ref().to_vec()
//    }
//
//    fn from_bytes(value: Cow<[u8]>) -> Self {
//        Self::new(MessageBuffer::from_vec(value.into_owned()))
//    }
//}

impl StorageValue for Vec<u8> {
    fn into_bytes(self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        buf
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let cur = Cursor::new(&value[..]);
        let mut de = Deserializer::new(cur);
        Deserialize::deserialize(&mut de).unwrap()
    }
}

/// Uses little-endian encoding.
impl StorageValue for DateTime<Utc> {
    fn into_bytes(self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        self.serialize(&mut Serializer::new(&mut buf)).unwrap();
        buf
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let cur = Cursor::new(&value[..]);
        let mut de = Deserializer::new(cur);
        Deserialize::deserialize(&mut de).unwrap()
    }
}

//impl StorageValue for Duration {
//    fn into_bytes(self) -> Vec<u8> {
//        let mut buffer = vec![0; Duration::field_size() as usize];
//        let from: Offset = 0;
//        let to: Offset = Duration::field_size();
//        self.write(&mut buffer, from, to);
//        buffer
//    }
//
//    fn from_bytes(value: Cow<[u8]>) -> Self {
//        #![allow(unsafe_code)]
//        let from: Offset = 0;
//        let to: Offset = Duration::field_size();
//        unsafe { Duration::read(&value, from, to) }
//    }
//}
//
//impl StorageValue for Round {
//    fn into_bytes(self) -> Vec<u8> {
//        self.0.into_bytes()
//    }
//
//    fn from_bytes(value: Cow<[u8]>) -> Self {
//        Round(u32::from_bytes(value))
//    }
//}
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    #[test]
//    fn u8_round_trip() {
//        let values = [u8::min_value(), 1, u8::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, u8::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn i8_round_trip() {
//        let values = [i8::min_value(), -1, 0, 1, i8::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, i8::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn u16_round_trip() {
//        let values = [u16::min_value(), 1, u16::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, u16::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn i16_round_trip() {
//        let values = [i16::min_value(), -1, 0, 1, i16::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, i16::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn u32_round_trip() {
//        let values = [u32::min_value(), 1, u32::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, u32::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn i32_round_trip() {
//        let values = [i32::min_value(), -1, 0, 1, i32::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, i32::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn u64_round_trip() {
//        let values = [u64::min_value(), 1, u64::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, u64::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn i64_round_trip() {
//        let values = [i64::min_value(), -1, 0, 1, i64::max_value()];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, i64::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn bool_round_trip() {
//        let values = [false, true];
//        for value in values.iter() {
//            let bytes = value.into_bytes();
//            assert_eq!(*value, bool::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn vec_round_trip() {
//        let values = [vec![], vec![1], vec![1, 2, 3], vec![255; 100]];
//        for value in values.iter() {
//            let bytes = value.clone().into_bytes();
//            assert_eq!(*value, Vec::<u8>::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn string_round_trip() {
//        let values: Vec<_> = ["", "e", "2", "hello"]
//            .iter()
//            .map(|v| v.to_string())
//            .collect();
//        for value in values.iter() {
//            let bytes = value.clone().into_bytes();
//            assert_eq!(*value, String::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn storage_value_for_system_time_round_trip() {
//        use chrono::TimeZone;
//
//        let times = [
//            Utc.timestamp(0, 0),
//            Utc.timestamp(13, 23),
//            Utc::now(),
//            Utc::now() + Duration::seconds(17) + Duration::nanoseconds(15),
//            Utc.timestamp(0, 999_999_999),
//            Utc.timestamp(0, 1_500_000_000), // leap second
//        ];
//
//        for time in times.iter() {
//            let buffer = time.into_bytes();
//            assert_eq!(*time, DateTime::from_bytes(Cow::Borrowed(&buffer)));
//        }
//    }
//
//    #[test]
//    fn storage_value_for_duration_round_trip() {
//        let durations = [
//            Duration::zero(),
//            Duration::max_value(),
//            Duration::min_value(),
//            Duration::nanoseconds(999_999_999),
//            Duration::nanoseconds(-999_999_999),
//            Duration::seconds(42) + Duration::nanoseconds(15),
//            Duration::seconds(-42) + Duration::nanoseconds(-15),
//        ];
//
//        for duration in durations.iter() {
//            let buffer = duration.into_bytes();
//            assert_eq!(*duration, Duration::from_bytes(Cow::Borrowed(&buffer)));
//        }
//    }
//
//    #[test]
//    fn round_round_trip() {
//        let values = [
//            Round::zero(),
//            Round::first(),
//            Round(100),
//            Round(u32::max_value()),
//        ];
//        for value in values.iter() {
//            let bytes = value.clone().into_bytes();
//            assert_eq!(*value, Round::from_bytes(Cow::Borrowed(&bytes)));
//        }
//    }
//
//    #[test]
//    fn uuid_round_trip() {
//        let values = [
//            Uuid::nil(),
//            Uuid::parse_str("936DA01F9ABD4d9d80C702AF85C822A8").unwrap(),
//            Uuid::parse_str("0000002a-000c-0005-0c03-0938362b0809").unwrap(),
//        ];
//
//        for value in values.iter() {
//            let bytes = value.clone().into_bytes();
//            assert_eq!(
//                *value,
//                <Uuid as StorageValue>::from_bytes(Cow::Borrowed(&bytes))
//            );
//        }
//    }
//}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero(){
        let zero1 = Zero::from_bytes(Cow::from(vec![]));
        assert_eq!(0, zero1.into_bytes().len());
    }
}