use serde::{Deserialize, Serialize};

use crate::crypto::{hash_bytes, Address, PublicKey, Signature};
use crate::error::{Result, ZinchaError};

fn entity_link_message(chain_id: &str, linked: &Address, entity: &Address) -> [u8; 32] {
    let message = format!(
        "zincha:entity_link:{}:{}:{}",
        chain_id,
        linked.to_hex(),
        entity.to_hex()
    );
    *hash_bytes(message.as_bytes()).as_bytes()
}

/// Data payload for `EntityLink` transactions.
///
/// The sender is the address being linked. `entity` is the canonical root
/// address this sender should resolve to for same-entity checks.
///
/// If `entity == sender`, the tx is invalid because the default resolution is
/// already "self". For non-self links, the entity root must co-sign the link
/// message so senders cannot claim arbitrary roots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityLinkData {
    pub entity: Address,
    #[serde(default)]
    pub authorizer_public_key: Option<PublicKey>,
    #[serde(default)]
    pub authorizer_signature: Option<Signature>,
}

/// Canonical committed entity-link row.
///
/// The mapping itself is immutable once written, so its locked storage deposit
/// stays attached to the row for the full lifetime of the link.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntityLinkRecord {
    pub entity: Address,
    pub storage_deposit: u64,
}

impl EntityLinkRecord {
    pub fn new(entity: Address, storage_deposit: u64) -> Self {
        Self {
            entity,
            storage_deposit,
        }
    }
}

impl EntityLinkData {
    pub fn verify(&self, sender: &Address, chain_id: &str) -> Result<()> {
        if &self.entity == sender {
            return Err(ZinchaError::InvalidTransaction(
                "EntityLink target must differ from sender".into(),
            ));
        }

        let authorizer_public_key = self.authorizer_public_key.as_ref().ok_or_else(|| {
            ZinchaError::InvalidTransaction("EntityLink requires authorizer_public_key".into())
        })?;
        let authorizer_signature = self.authorizer_signature.as_ref().ok_or_else(|| {
            ZinchaError::InvalidTransaction("EntityLink requires authorizer_signature".into())
        })?;

        if authorizer_public_key.to_address() != self.entity {
            return Err(ZinchaError::InvalidTransaction(
                "EntityLink authorizer must match entity root".into(),
            ));
        }

        let message = entity_link_message(chain_id, sender, &self.entity);
        authorizer_public_key.verify(&message, authorizer_signature)
    }
}

#[cfg(test)]
mod tests {
    use super::EntityLinkRecord;
    use crate::crypto::Address;

    #[test]
    fn test_entity_link_record_deserialize_requires_storage_deposit() {
        let value = serde_json::to_value(EntityLinkRecord::new(Address([0x11; 20]), 7))
            .expect("serialize canonical entity link record");
        let mut object = value
            .as_object()
            .expect("entity link record serialized as object")
            .clone();
        object.remove("storage_deposit");

        let err = serde_json::from_value::<EntityLinkRecord>(serde_json::Value::Object(object))
            .unwrap_err();
        assert!(
            err.to_string().contains("storage_deposit"),
            "unexpected error: {}",
            err
        );
    }
}
