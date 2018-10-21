use super::{public_to_address, Address, Error, Message, Public, Secret, SECP256K1};
use common::{to_hex, to_keccak};
use crypto::{hash, CryptoHash, Hash};
use ethereum_types::{H256, H520};
use hex::FromHex;
use rmps::{Deserializer, Serializer};
use secp256k1::key::{PublicKey, SecretKey};
use secp256k1::{Error as SecpError, Message as SecpMessage, RecoverableSignature, RecoveryId};
use serde::de::{Error as SerdeDeError, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer as StdDeserializer, Serialize, Serializer as StdSerializer};
use std::cmp::PartialEq;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

pub const SIGNATURE_SIZE: usize = 65;
pub const SIGNATURE_R_SIZE: usize = 32;
pub const SIGNATURE_S_SIZE: usize = 32;

/// Signature encoded
/// as RSV components
//#[derive(Deserialize, Serialize)]
pub struct Signature([u8; SIGNATURE_SIZE]);

impl Signature {
    /// Get a slice into the `r` portion of the data.
    pub fn r(&self) -> &[u8] {
        &self.0[0..SIGNATURE_R_SIZE]
    }

    /// Get a slice into the `s` portion of the data.
    pub fn s(&self) -> &[u8] {
        &self.0[SIGNATURE_R_SIZE..(SIGNATURE_SIZE + SIGNATURE_S_SIZE)]
    }

    /// Get the recovery byte
    pub fn v(&self) -> u8 {
        self.0[64]
    }

    /// Encode the signature into RSV array (V altered to be in `Electrum` notation).
    pub fn into_electrum(mut self) -> [u8; SIGNATURE_SIZE] {
        self.0[64] += 27;
        self.0
    }

    /// Parse bytes as a signature encoded as RSV (V in "Electrum" notation).
    /// May be return empty (invalid) signature if given data has invalid length.
    pub fn from_electrum(data: &[u8]) -> Self {
        if data.len() != SIGNATURE_SIZE || data[64] < 27 {
            // fallback to empty (invalid) signature
            return Signature::default();
        }

        let mut sig = [0u8; SIGNATURE_SIZE];
        sig.copy_from_slice(data);
        sig[64] -= 27;
        Signature(sig)
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self::from_electrum(data)
    }

    /// Check if this is a "low" signature
    pub fn is_low_s(&self) -> bool {
        H256::from_slice(self.s())
            <= "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0".into()
    }

    /// Check if each_component of the signature is in range.
    pub fn is_valid(&self) -> bool {
        self.v() <= 1
            && H256::from_slice(self.r())
                < "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".into()
            && H256::from_slice(self.r()) >= 1.into()
            && H256::from_slice(self.s())
                < "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".into()
            && H256::from_slice(self.s()) >= 1.into()
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: StdSerializer,
    {
        let mut seq = serializer.serialize_tuple(self.0.len())?;
        for elem in &self.0[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: StdDeserializer<'de>,
    {
        struct ArrayVisitor {}
        impl<'de> Visitor<'de> for ArrayVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 65))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Signature, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [u8::default(); 65];
                for i in 0..65 {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| SerdeDeError::invalid_length(i, &self))?;
                }
                Ok(Signature(arr))
            }
        }

        let visitor = ArrayVisitor {};
        deserializer.deserialize_tuple(65, visitor)
    }
}
// manual implementation large arrays don't have trait impls by default.
// remove when integer generics exist
impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        &self.0[..] == &other.0[..]
    }
}

// manual implementation required in Rust 1.13+, see `std::cmp::AssertParamIsEq`.
impl Eq for Signature {}

// also manual for the same reason, but the pretty printing might be useful.
impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Signature")
            .field("r", &to_hex(&self.0[0..32]))
            .field("s", &to_hex(&self.0[32..64]))
            .field("v", &to_hex(&self.0[64..65]))
            .finish()
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", to_hex(&self.0[..]))
    }
}

impl FromStr for Signature {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let dec_hex = ::common::from_hex(s);
        match dec_hex {
            Ok(ref hex) if hex.len() == 65 => {
                let mut data = [0; SIGNATURE_SIZE];
                data.copy_from_slice(&hex[0..65]);
                Ok(Signature(data))
            }
            _ => Err(Error::InvalidSignature),
        }
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0; 65])
    }
}

impl CryptoHash for Signature {
    fn hash(&self) -> Hash {
        let mut buf: Vec<u8> = Vec::new();
        self.0.serialize(&mut Serializer::new(&mut buf)).unwrap();
        hash(&buf)
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        Signature(self.0)
    }
}

impl From<[u8; 65]> for Signature {
    fn from(s: [u8; 65]) -> Self {
        Signature(s)
    }
}

impl Into<[u8; 65]> for Signature {
    fn into(self) -> [u8; 65] {
        self.0
    }
}

impl From<Signature> for H520 {
    fn from(s: Signature) -> Self {
        H520::from(s.0)
    }
}

impl From<H520> for Signature {
    fn from(bytes: H520) -> Self {
        Signature(bytes.into())
    }
}

impl Deref for Signature {
    type Target = [u8; 65];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn sign(secret: &Secret, message: &Message) -> Result<Signature, Error> {
    let context = &SECP256K1;
    let sec = SecretKey::from_slice(context, &secret)?;
    let s = context.sign_recoverable(&SecpMessage::from_slice(&message[..])?, &sec)?;
    let (rec_id, data) = s.serialize_compact(context);
    let mut data_arr = [0; SIGNATURE_SIZE];

    // no need to check if s is low, it always is
    let signature_v_offset = SIGNATURE_R_SIZE + SIGNATURE_S_SIZE;
    data_arr[0..signature_v_offset].copy_from_slice(&data[0..signature_v_offset]);
    data_arr[signature_v_offset] = rec_id.to_i32() as u8;
    Ok(Signature(data_arr))
}

pub fn sign_bytes(secret: &Secret, bytes: &[u8]) -> Result<Signature, Error> {
    let digest = to_keccak(bytes);
    let message = Message::from_slice(&digest);
    sign(secret, &message)
}

/// |compress-0|1~64|
pub fn verify_public(
    public: &Public,
    signature: &Signature,
    message: &Message,
) -> Result<bool, Error> {
    let context = &SECP256K1;
    let v_off = SIGNATURE_S_SIZE + SIGNATURE_R_SIZE;
    let rsig = RecoverableSignature::from_compact(
        context,
        &signature[0..v_off],
        RecoveryId::from_i32(signature[v_off] as i32)?,
    )?;
    let sig = rsig.to_standard(context);

    let pdata: [u8; SIGNATURE_SIZE] = {
        let mut temp = [4u8; SIGNATURE_SIZE];
        temp[1..SIGNATURE_SIZE].copy_from_slice(&**public);
        temp
    };

    let publ = PublicKey::from_slice(context, &pdata)?;
    match context.verify(&SecpMessage::from_slice(&message[..])?, &sig, &publ) {
        Ok(_) => Ok(true),
        Err(SecpError::IncorrectSignature) => Ok(false),
        Err(x) => Err(Error::from(x)),
    }
}

pub fn verify_address(
    address: &Address,
    signature: &Signature,
    message: &Message,
) -> Result<bool, Error> {
    let public = recover(signature, message)?;
    let recovered_address = public_to_address(&public);
    Ok(address == &recovered_address)
}

pub fn recover(signature: &Signature, message: &Message) -> Result<Public, Error> {
    let context = &SECP256K1;
    let v_off = SIGNATURE_R_SIZE + SIGNATURE_S_SIZE;
    let rsig = RecoverableSignature::from_compact(
        context,
        &signature[0..v_off],
        RecoveryId::from_i32(signature[v_off] as i32)?,
    )?;
    let pubkey = context.recover(&SecpMessage::from_slice(&message[..])?, &rsig)?;
    let serialized = pubkey.serialize_vec(context, false);

    let mut public = Public::default();
    public.copy_from_slice(&serialized[1..65]);
    Ok(public)
}

#[cfg(test)]
mod test {
    use super::{recover, sign, sign_bytes, verify_address, verify_public, Signature};
    use ethkey::{random::Random, Generator, Message};
    use std::io::{self, Write};
    use std::str::FromStr;

    #[test]
    fn vrs_conversion() {
        let keypair = Random.generate().unwrap();
        let message = Message::default();
        let signature = sign(keypair.secret(), &message).unwrap();

        // when
        let vrs = signature.clone().into_electrum();
        let from_vrs = Signature::from_electrum(&vrs);

        // then
        assert_eq!(signature, from_vrs);
    }

    #[test]
    fn signature_to_and_from_str() {
        let keypair = Random.generate().unwrap();
        let message = Message::default();
        let signature = sign(keypair.secret(), &message).unwrap();
        let string = format!("{}", signature);
        let deserialized = Signature::from_str(&string).unwrap();
        assert_eq!(signature, deserialized);
    }

    #[test]
    fn sign_and_recover_public() {
        let keypair = Random.generate().unwrap();
        let message = Message::default();
        let signature = sign(keypair.secret(), &message).unwrap();
        assert_eq!(keypair.public(), &recover(&signature, &message).unwrap());
    }

    #[test]
    fn sign_and_verify_public() {
        let keypair = Random.generate().unwrap();
        let message = Message::default();
        let signature = sign(keypair.secret(), &message).unwrap();
        assert!(verify_public(keypair.public(), &signature, &message).unwrap());
    }

    #[test]
    fn sign_and_verify_address() {
        let keypair = Random.generate().unwrap();
        let message = Message::default();
        let signature = sign(keypair.secret(), &message).unwrap();
        assert!(verify_address(&keypair.address(), &signature, &message).unwrap());
    }

    #[test]
    fn sign_deserialize_serialize() {
        let keypair = Random.generate().unwrap();
        let message = Message::default();
        let signature: Signature = sign(keypair.secret(), &message).unwrap();
        let serialized = serde_json::to_string(&signature).unwrap();
        let signature_deserialize: Signature = serde_json::from_str(&serialized).unwrap();
        writeln!(io::stdout(), "{}", serialized).unwrap();
        writeln!(io::stdout(), "{}", signature).unwrap();
        writeln!(io::stdout(), "{}", signature_deserialize).unwrap();
    }

    #[test]
    fn t_sign_bytes() {
        let keypair = Random.generate().unwrap();
        let signature1: Signature = sign_bytes(keypair.secret(), &[90_u8; 109]).unwrap();
        {
            let serialized = serde_json::to_string(&signature1).unwrap();
            let signature_deserialize: Signature = serde_json::from_str(&serialized).unwrap();
            writeln!(io::stdout(), "{}", serialized).unwrap();
            writeln!(io::stdout(), "{}", signature1).unwrap();
            writeln!(io::stdout(), "{}", signature_deserialize).unwrap();
        }
        let signature2: Signature = sign_bytes(keypair.secret(), &[90_u8; 109]).unwrap();
        {
            let serialized = serde_json::to_string(&signature2).unwrap();
            let signature_deserialize: Signature = serde_json::from_str(&serialized).unwrap();
            writeln!(io::stdout(), "{}", serialized).unwrap();
            writeln!(io::stdout(), "{}", signature2).unwrap();
            writeln!(io::stdout(), "{}", signature_deserialize).unwrap();
        }
        let signature3: Signature = sign_bytes(keypair.secret(), &[79_u8; 109]).unwrap();
        {
            let serialized = serde_json::to_string(&signature3).unwrap();
            let signature_deserialize: Signature = serde_json::from_str(&serialized).unwrap();
            writeln!(io::stdout(), "{}", serialized).unwrap();
            writeln!(io::stdout(), "{}", signature3).unwrap();
            writeln!(io::stdout(), "{}", signature_deserialize).unwrap();
        }
        assert_eq!(signature1, signature2);
        assert_ne!(signature1, signature3);
    }
}
