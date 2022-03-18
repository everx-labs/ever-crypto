use aes_ctr::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use core::ops::Range;
use ed25519::signature::Verifier;
use sha2::Digest;
use std::{
    convert::TryInto, fmt::{self, Debug, Display, Formatter},
    sync::Arc};

use ton_api::{deserialize_boxed, IntoBoxed, ton::{self, pub_::publickey::Ed25519} };
use ton_types::{error, fail, Result, UInt256};

pub trait KeyOption: Sync + Send + Debug {
    fn id(&self) -> &Arc<KeyId>;
    fn type_id(&self) -> i32;
    fn pub_key(&self) -> Result<&[u8]>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()>;
    fn into_public_key_tl(&self) -> Result<ton::PublicKey>;
    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]>;
    fn shared_secret(&self, other_pub_key: &[u8]) -> Result<[u8; 32]>;
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub struct AesCtr {
    aes_ctr: aes_ctr::Aes256Ctr
}

impl AesCtr {
    pub fn with_params(key: &[u8], ctr: &[u8]) -> Self {
        let aes_ctr = aes_ctr::Aes256Ctr::new(
            aes_ctr::cipher::generic_array::GenericArray::from_slice(key),
            aes_ctr::cipher::generic_array::GenericArray::from_slice(ctr)
        );
        Self { aes_ctr }
    }
    pub fn apply_keystream(&mut self, buf: &mut Vec<u8>, range: Range<usize>) {
        self.aes_ctr.apply_keystream(&mut buf[range]);
    }
}

#[derive(Debug)]
pub struct Ed25519KeyOption {
    id: Arc<KeyId>,
    pub_key: Option<[u8; Self::PUB_KEY_SIZE]>,
    exp_key: Option<[u8; Self::EXP_KEY_SIZE]>
}

impl Ed25519KeyOption {
    
    pub const KEY_TYPE: i32 = 1209251014;
    pub const EXP_KEY_SIZE: usize = 64;
    pub const PVT_KEY_SIZE: usize = 32;
    pub const PUB_KEY_SIZE: usize = 32;

    /// Create from Ed25519 expanded secret key raw data
    pub fn from_expanded_key(exp_key: &[u8; Self::EXP_KEY_SIZE]) -> Result<Arc<dyn KeyOption>> {
        Self::create_from_expanded_key(ed25519_dalek::ExpandedSecretKey::from_bytes(exp_key)?)
    }

    /// Create from Ed25519 secret key raw data
    pub fn from_private_key(pvt_key: &[u8; Self::PVT_KEY_SIZE]) -> Result<Arc<dyn KeyOption>> {
        Self::create_from_expanded_key(
            ed25519_dalek::ExpandedSecretKey::from(&ed25519_dalek::SecretKey::from_bytes(pvt_key)?)
        )
    }

    /// Create from Ed25519 secret key raw data and export JSON
    pub fn from_private_key_with_json(
        pvt_key: &[u8; Self::PVT_KEY_SIZE]
    ) -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        Self::create_from_private_key_with_json(ed25519_dalek::SecretKey::from_bytes(pvt_key)?)
    }

    /// Create from Ed25519 secret key JSON 
    pub fn from_private_key_json(src: &KeyOptionJson) -> Result<Arc<dyn KeyOption>> {
        match src.type_id {
            Self::KEY_TYPE => match &src.pvt_key {
                Some(key) => {
                    if src.pub_key.is_some() {
                        fail!("No public key expected");
                    }
                    let key = base64::decode(key)?;
                    if key.len() != Self::PVT_KEY_SIZE {
                        fail!("Bad private key");
                    } 
                    Self::from_private_key(key.as_slice().try_into()?)
                },
                None => fail!("No private key")
            },
            _ => fail!("Type-id {} is not supported for Ed25519 private key", src.type_id)
        }
    }

    /// Create from Ed25519 public key raw data
    pub fn from_public_key(pub_key: &[u8; Self::PUB_KEY_SIZE]) -> Arc<dyn KeyOption> {
        Arc::new(
            Self {
                id: Self::calc_id(Self::KEY_TYPE, pub_key), 
                pub_key: Some(*pub_key), 
                exp_key: None
            }
        )
    }

    /// Create from Ed265519 public key JSON 
    pub fn from_public_key_json(src: &KeyOptionJson) -> Result<Arc<dyn KeyOption>> {
        match src.type_id {
            Self::KEY_TYPE => match &src.pub_key {
                Some(key) => {
                    if src.pvt_key.is_some() {
                        fail!("No private key expected");
                    }
                    let key = base64::decode(key)?;
                    if key.len() != Self::PUB_KEY_SIZE {
                        fail!("Bad public key");
                    } 
                    Ok(Self::from_public_key(key.as_slice().try_into()?))
                },
                None => fail!("No public key")
            },
            _ => fail!("Type-id {} is not supported for Ed25519 public key", src.type_id)
        }
    }

    /// Create from Ed25519 public key TL object
    pub fn from_public_key_tl(src: &ton::PublicKey) -> Result<Arc<dyn KeyOption>> {
        if let ton::PublicKey::Pub_Ed25519(key) = src {
            Ok(Self::from_public_key(&key.key.as_slice()))
        } else {
            fail!("Unsupported public key type {:?}", src)
        }
    }

    /// Create from serialized Ed25519 public key TL object
    pub fn from_public_key_tl_serialized(pub_key: &[u8]) -> Result<Arc<dyn KeyOption>> {
        match deserialize_boxed(pub_key)?.downcast::<ton::PublicKey>() {
            Ok(pub_key) => Self::from_public_key_tl(&pub_key),
            Err(key) => fail!("Unsupported PublicKey data {:?}", key)
        }
    }

    /// Generate new Ed25519 key
    pub fn generate() -> Result<Arc<dyn KeyOption>> {
        Self::create_from_expanded_key(
            ed25519_dalek::ExpandedSecretKey::from(
                &ed25519_dalek::SecretKey::generate(&mut rand::thread_rng())
            )
        )
    }

    /// Generate new Ed25519 key and export JSON
    pub fn generate_with_json() -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        Self::create_from_private_key_with_json(
            ed25519_dalek::SecretKey::generate(&mut rand::thread_rng())
        )
    }
    
    fn create_from_expanded_key(
        exp_key: ed25519_dalek::ExpandedSecretKey
    ) -> Result<Arc<dyn KeyOption>> {
        let pub_key = ed25519_dalek::PublicKey::from(&exp_key).to_bytes();
        let exp_key = exp_key.to_bytes().try_into()?;
        let ret = Self {
            id: Self::calc_id(Self::KEY_TYPE, &pub_key), 
            pub_key: Some(pub_key), 
            exp_key: Some(exp_key)
        };
        Ok(Arc::new(ret))
    }

    fn create_from_private_key_with_json(
        pvt_key: ed25519_dalek::SecretKey
    ) -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        let ret = Self::create_from_expanded_key(ed25519_dalek::ExpandedSecretKey::from(&pvt_key))?;
        let json = KeyOptionJson {
            type_id: Self::KEY_TYPE,
            pub_key: None,
            pvt_key: Some(base64::encode(&pvt_key.to_bytes()))
        };
        Ok((json, ret))
    }

    // Calculate key ID
    fn calc_id(type_id: i32, pub_key: &[u8; Self::PUB_KEY_SIZE]) -> Arc<KeyId> {
        let mut sha = sha2::Sha256::new();
        sha.update(&type_id.to_le_bytes());
        sha.update(pub_key);
        KeyId::from_data(sha.finalize().into())
    }

    fn exp_key(&self) -> Result<&[u8; Self::EXP_KEY_SIZE]> {
        if let Some(exp_key) = self.exp_key.as_ref() {
            Ok(exp_key)
        } else {
            fail!("No expansion key set for key option {}", self.id())
        }
    }

}

impl KeyOption for Ed25519KeyOption {
    
    /// Get key id 
    fn id(&self) -> &Arc<KeyId> {
        &self.id
    }
    
    /// Get type id 
    fn type_id(&self) -> i32 {
        Self::KEY_TYPE
    }
    
    /// Get public key
    fn pub_key(&self) -> Result<&[u8]> {
        if let Some(pub_key) = self.pub_key.as_ref() {
            Ok(pub_key)
        } else {
            fail!("No public key set for key option {}", self.id())
        }
    }

    /// Export into TL object with public key 
    fn into_public_key_tl(&self) -> Result<ton::PublicKey> {
        let pub_key = self.pub_key()?;
        let ret = Ed25519 { 
            key: UInt256::with_array(pub_key.try_into()?)
        }.into_boxed();
        Ok(ret)
    }
    
    /// Calculate signature
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let exp_key = ed25519_dalek::ExpandedSecretKey::from_bytes(self.exp_key()?)?;
        let pub_key = if let Ok(key) = self.pub_key() {
            ed25519_dalek::PublicKey::from_bytes(key)?
        } else {
            ed25519_dalek::PublicKey::from(&exp_key)
        };
        Ok(exp_key.sign(data, &pub_key).to_bytes().to_vec())
    }

    /// Verify signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let pub_key = ed25519_dalek::PublicKey::from_bytes(
            self.pub_key()?
        )?;
        pub_key.verify(data, &ed25519::Signature::from_bytes(signature)?)?;
        Ok(())
    }

    fn shared_secret(&self, other_pub_key: &[u8]) -> Result<[u8; 32]> {
        let point = curve25519_dalek::edwards::CompressedEdwardsY(other_pub_key.try_into()?)
            .decompress()
            .ok_or_else(|| error!("Bad public key data"))?
            .to_montgomery()
            .to_bytes();
        let exp_key = self.exp_key()?;
        Ok(x25519_dalek::x25519(exp_key[..Self::PVT_KEY_SIZE].try_into()?, point))
    }

    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]> {
        Ok(self.exp_key()?)
    }

}

/// ADNL key ID (node ID)
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct KeyId([u8; 32]);

impl KeyId {
   pub fn from_data(data: [u8; 32]) -> Arc<Self> {
       Arc::new(Self(data))
   }
   pub fn data(&self) -> &[u8; 32] {
       &self.0
   }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", base64::encode(self.data()))
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct KeyOptionJson {
    type_id: i32,
    pub_key: Option<String>,
    pvt_key: Option<String>
}
