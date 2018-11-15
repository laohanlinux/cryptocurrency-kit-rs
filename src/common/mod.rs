use std::io::Cursor;
use std::iter;

use ethereum_types::H256;
use hex;
use keccak_hash::keccak;
use rmps::decode::Error;
use rmps::{Deserializer, Serializer};
use rustc_hex::ToHex;
use serde::{Deserialize, Deserializer as stdDer, Serialize, Serializer as stdSer};
use sha3::{Digest, Sha3_256};

pub fn to_hex<T: AsRef<[u8]>>(data: T) -> String {
    hex::encode(data)
}

pub fn from_hex<T: AsRef<[u8]>>(data: T) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(data)
}

pub fn to_sha3(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::default();
    hasher.input(data);
    hasher.result().to_vec()
}

pub fn to_keccak<T: AsRef<[u8]>>(data: T) -> H256 {
    keccak(data)
}

pub fn to_msgpack_vec<T: stdSer + Serialize>(obj: T, buf: &mut [u8]) {
    obj.serialize(&mut Serializer::new(buf)).unwrap();
}

pub fn from_msgpack<T: 'static + stdSer + Deserialize<'static> + Serialize>(buf: &[u8]) -> T {
    let cur = Cursor::new(buf);
    let mut de = Deserializer::new(cur);
    Deserialize::deserialize(&mut de).unwrap()
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    pub root: Option<Box<MerkleNode>>,
}

#[derive(Debug, Clone)]
pub struct MerkleNode {
    pub data: Box<Vec<u8>>,
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
}

impl MerkleTree {
    // just build the root
    pub fn new_merkle_tree(mut data: Vec<Vec<u8>>) -> MerkleTree {
        // Fuck
        let clone_data = {
            if data.len() % 2 != 0 {
                let clone_data = {
                    data.last().unwrap()
                };
                Some(clone_data.clone())
            } else {
                None
            }
        };
        if clone_data.is_some() {
            data.push(clone_data.unwrap());
        }

        let mut nodes = vec![];

        data.iter().for_each(
            |dataum| nodes.push(MerkleNode::new(dataum)),
        );

        loop {
            let mut new_level = vec![];
            let (mut i, mut j) = (0, 0);
            while i < &nodes.len() / 2 {
                let node = MerkleNode::new_merkle_node(nodes[j].clone(), nodes[j + 1].clone());
                new_level.push(node);
                j += 2;
                i += 1;
            }
            nodes = new_level;
            if nodes.len() == 1 {
                break;
            }
        }
        MerkleTree { root: Some(Box::new(nodes.pop().unwrap())) }
    }
}

impl MerkleNode {
    fn new(data: &[u8]) -> MerkleNode {
        let mut mn: MerkleNode = Default::default();
        mn.data = Box::new(to_sha3(data).to_vec());
        mn
    }
    fn new_merkle_node(left: MerkleNode, right: MerkleNode) -> MerkleNode {
        let mut merkle_tree_node: MerkleNode = Default::default();
        let mut hash_data = Vec::with_capacity(left.data.len() + right.data.len());
        hash_data.extend(iter::repeat(0).take(left.data.len() + right.data.len()));
        hash_data[..left.data.len()].clone_from_slice(&left.data);
        hash_data[left.data.len()..].clone_from_slice(&right.data);

        let hash = to_sha3(&hash_data);
        merkle_tree_node.data = Box::new(hash);
        merkle_tree_node
    }
}

impl Default for MerkleNode {
    fn default() -> MerkleNode {
        MerkleNode {
            data: Box::new(vec![]),
            left: None,
            right: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};

    #[test]
    fn keccak_sha() {
        let v = vec![1, 2, 3];
        let sha3 = to_sha3(&v);
        let keccak = to_keccak(&v);
        writeln!(io::stdout(), "{:?}", sha3).unwrap();
        writeln!(io::stdout(), "{:?}", &keccak[0..32]).unwrap();
    }

    #[test]
    fn merkle_tree() {
        let vv = vec![vec![1, 3, 4], vec![4, 51, 3], vec![98]];
        let merkle_tree = MerkleTree::new_merkle_tree(vv);
        writeln!(io::stdout(), "root {:?}", merkle_tree.root.unwrap()).unwrap();
    }
}