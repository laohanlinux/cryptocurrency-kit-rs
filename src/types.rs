use rmps::decode::Error;
use rmps::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Zero;