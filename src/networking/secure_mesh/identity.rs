use std::{
    net::SocketAddr,
    ops::{Index, IndexMut},
};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentities {
    identities: Vec<NodeIdentity>,
}

impl NodeIdentities {
    pub fn new(identities: Vec<NodeIdentity>) -> Self {
        NodeIdentities { identities }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }
}

impl Index<usize> for NodeIdentities {
    type Output = NodeIdentity;

    fn index(&self, index: usize) -> &Self::Output {
        &self.identities[index]
    }
}

impl IndexMut<usize> for NodeIdentities {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.identities[index]
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub address: SocketAddr,
    #[serde(with = "hex_key_serde")]
    pub public_key: VerifyingKey,
}

mod hex_key_serde {
    use base64::{Engine as _, prelude::BASE64_STANDARD};
    use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = BASE64_STANDARD.encode(key.as_bytes());
        serializer.serialize_str(&string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD.decode(&s).map_err(D::Error::custom)?;
        let bytes_fixed: [u8; PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("Invalid key length"))?;

        VerifyingKey::from_bytes(&bytes_fixed).map_err(D::Error::custom)
    }
}
