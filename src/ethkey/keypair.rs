// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use std::fmt;
use parity_crypto::Keccak256;
use ethereum_types::{H256, H160, H512};

use secp256k1::key;
use common::{to_hex, to_fixed_array, to_fixed_array_20, to_fixed_array_64};
use super::{Secret, SECP256K1, Public, Address, Error};
use chrono::format::Numeric::Hour12;
use proc_macro::bridge::TokenTree::Punct;

pub fn public_to_address(public: &Public) -> Address {
    let hash = public.keccak256();
    let result = to_fixed_array_20(&hash[12..]);
    Address::from(result)
}

#[derive(Debug, Clone, PartialEq)]
/// Secp256k1 key pair
pub struct KeyPair {
    secret: Secret,
    public: Public,
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "secret:  {}", self.secret.to_hex())?;
        writeln!(f, "public:  {}", to_hex(self.public))?;
        write!(f, "address: {}", to_hex(self.address()))
    }
}

impl KeyPair {
    /// Create a pair from secret key
    pub fn from_secret(secret: Secret) -> Result<KeyPair, Error> {
        let context = &SECP256K1;
        let s: key::SecretKey = key::SecretKey::from_slice(context, &secret[..])?;
        let pub_key = key::PublicKey::from_secret_key(context, &s)?;
        let serialized = pub_key.serialize_vec(context, false);

        let mut public = H512::from(to_fixed_array_64(&serialized[1..65]));

        let keypair = KeyPair {
            secret,
            public,
        };

        Ok(keypair)
    }


    pub fn from_secret_slice(slice: &[u8]) -> Result<KeyPair, Error> {
        Self::from_secret(Secret::from_unsafe_slice(slice)?)
    }

    pub fn from_keypair(sec: key::SecretKey, publ: key::PublicKey) -> Self {
        let context = &SECP256K1;
        let serialized = publ.serialize_vec(context, false);
        let secret = Secret::from(sec);
        let public = H512::from(to_fixed_array_64(&serialized[1..65]));

        KeyPair {
            secret,
            public,
        }
    }

    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    pub fn public(&self) -> &Public {
        &self.public
    }

    pub fn address(&self) -> Address {
        public_to_address(self.public())
    }
}

/// TODO
#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::str::FromStr;
    use super::KeyPair;
    use super::Secret;
}