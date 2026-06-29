use serde::{Deserialize, Serialize};

use crate::crypto::{hash_bytes, Address, Hash256, Keypair, PublicKey, Signature};
use crate::error::{Result, ZinchaError};

pub const MAX_VALIDATOR_EXECUTOR_SERVICES: usize = 32;
pub const MAX_VALIDATOR_EXECUTOR_ENDPOINT_BYTES: usize = 256;
pub const MAX_VALIDATOR_VRF_OUTPUT_BYTES: usize = 128;
pub const MAX_VALIDATOR_VRF_PROOF_BYTES: usize = 512;
const VALIDATOR_VRF_PROOF_DOMAIN: &[u8] = b"zincha_validator_vrf_contribution_v2";
const VALIDATOR_VRF_OUTPUT_DOMAIN: &[u8] = b"zincha_validator_vrf_output_v2";
const VALIDATOR_VRF_COMMITMENT_DOMAIN: &[u8] = b"zincha_validator_vrf_commitment_v1";
const VALIDATOR_VRF_EVIDENCE_DOMAIN: &[u8] = b"zincha_validator_vrf_evidence_v1";

/// One executor service endpoint claimed by a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorExecutorService {
    pub partition_id: u32,
    pub rpc_endpoint: String,
    pub executor_public_key: PublicKey,
}

/// Canonical validator metadata update payload.
///
/// This is used both during `ValidatorRegister` and `ValidatorUpdate` so a
/// validator can publish executor service claims and its canonical VRF identity
/// without exiting the validator set.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidatorUpdateData {
    #[serde(default)]
    pub executor_services: Vec<ValidatorExecutorService>,
    #[serde(default)]
    pub vrf_public_key: Option<PublicKey>,
}

/// Canonical payload for an epoch VRF contribution.
///
/// Validators reveal one contribution for a specific target epoch after first
/// locking it in with `ValidatorVrfCommitData`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidatorVrfCommitData {
    pub target_epoch: u64,
    pub commitment: Hash256,
}

/// Canonical payload for an epoch VRF contribution reveal.
///
/// Validators reveal one contribution for a specific target epoch after first
/// locking it in with `ValidatorVrfCommitData`. The proof is validated against
/// the validator's canonical VRF key and must match the earlier commitment.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidatorVrfContributionData {
    pub target_epoch: u64,
    #[serde(default)]
    pub vrf_output: Vec<u8>,
    #[serde(default)]
    pub vrf_proof: Vec<u8>,
}

/// Canonical key for one validator's epoch-randomness contribution.
#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ValidatorVrfContributionKey {
    pub target_epoch: u64,
    pub validator: Address,
}

impl ValidatorVrfContributionKey {
    pub fn new(target_epoch: u64, validator: Address) -> Self {
        Self {
            target_epoch,
            validator,
        }
    }
}

/// Canonical stored validator contribution record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVrfContributionRecord {
    pub validator: Address,
    pub target_epoch: u64,
    pub commitment: Hash256,
    pub submitted_in_block: u64,
    #[serde(default)]
    pub revealed_in_block: Option<u64>,
    #[serde(default)]
    pub vrf_output: Vec<u8>,
    #[serde(default)]
    pub vrf_proof: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ValidatorVrfEvidenceKind {
    Commit,
    Contribution,
}

impl ValidatorVrfEvidenceKind {
    pub fn rank(self) -> u8 {
        match self {
            Self::Commit => 0,
            Self::Contribution => 1,
        }
    }
}

/// Consensus-native signed validator VRF evidence.
///
/// This replaces the old nonce/fee-backed VRF transactions in canonical block
/// production. Evidence is signed by the validator's canonical key, committed
/// by block system-operation roots, and applied without account nonce or gas
/// side effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignedValidatorVrfEvidence {
    Commit {
        validator: Address,
        target_epoch: u64,
        commitment: Hash256,
        public_key: PublicKey,
        signature: Signature,
    },
    Contribution {
        validator: Address,
        target_epoch: u64,
        #[serde(default)]
        vrf_output: Vec<u8>,
        #[serde(default)]
        vrf_proof: Vec<u8>,
        public_key: PublicKey,
        signature: Signature,
    },
}

impl SignedValidatorVrfEvidence {
    pub fn new_commit(keypair: &Keypair, target_epoch: u64, commitment: Hash256) -> Self {
        let validator = keypair.address();
        let public_key = keypair.public_key();
        let signable =
            Self::commit_signable_bytes(&validator, target_epoch, &commitment, &public_key);
        let signature = keypair.sign(&signable);
        Self::Commit {
            validator,
            target_epoch,
            commitment,
            public_key,
            signature,
        }
    }

    pub fn new_contribution(
        keypair: &Keypair,
        target_epoch: u64,
        vrf_output: Vec<u8>,
        vrf_proof: Vec<u8>,
    ) -> Self {
        let validator = keypair.address();
        let public_key = keypair.public_key();
        let signable = Self::contribution_signable_bytes(
            &validator,
            target_epoch,
            &vrf_output,
            &vrf_proof,
            &public_key,
        );
        let signature = keypair.sign(&signable);
        Self::Contribution {
            validator,
            target_epoch,
            vrf_output,
            vrf_proof,
            public_key,
            signature,
        }
    }

    pub fn validator(&self) -> &Address {
        match self {
            Self::Commit { validator, .. } | Self::Contribution { validator, .. } => validator,
        }
    }

    pub fn target_epoch(&self) -> u64 {
        match self {
            Self::Commit { target_epoch, .. } | Self::Contribution { target_epoch, .. } => {
                *target_epoch
            }
        }
    }

    pub fn kind(&self) -> ValidatorVrfEvidenceKind {
        match self {
            Self::Commit { .. } => ValidatorVrfEvidenceKind::Commit,
            Self::Contribution { .. } => ValidatorVrfEvidenceKind::Contribution,
        }
    }

    pub fn pool_key(&self) -> ValidatorVrfEvidenceKey {
        ValidatorVrfEvidenceKey {
            target_epoch: self.target_epoch(),
            kind: self.kind(),
            validator: self.validator().clone(),
        }
    }

    pub fn hash(&self) -> Hash256 {
        let encoded = bincode::serialize(self)
            .expect("SignedValidatorVrfEvidence serialization should not fail");
        let mut bytes = Vec::with_capacity(VALIDATOR_VRF_EVIDENCE_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(VALIDATOR_VRF_EVIDENCE_DOMAIN);
        bytes.extend_from_slice(&encoded);
        hash_bytes(&bytes)
    }

    pub fn verify_signature(&self) -> Result<()> {
        match self {
            Self::Commit {
                validator,
                target_epoch,
                commitment,
                public_key,
                signature,
            } => {
                if public_key.to_address() != *validator {
                    return Err(ZinchaError::InvalidSignature(
                        "validator VRF commit signer does not match validator".to_string(),
                    ));
                }
                public_key.verify(
                    &Self::commit_signable_bytes(validator, *target_epoch, commitment, public_key),
                    signature,
                )
            }
            Self::Contribution {
                validator,
                target_epoch,
                vrf_output,
                vrf_proof,
                public_key,
                signature,
            } => {
                if public_key.to_address() != *validator {
                    return Err(ZinchaError::InvalidSignature(
                        "validator VRF contribution signer does not match validator".to_string(),
                    ));
                }
                public_key.verify(
                    &Self::contribution_signable_bytes(
                        validator,
                        *target_epoch,
                        vrf_output,
                        vrf_proof,
                        public_key,
                    ),
                    signature,
                )
            }
        }
    }

    pub fn commit_payload(&self) -> Option<ValidatorVrfCommitData> {
        match self {
            Self::Commit {
                target_epoch,
                commitment,
                ..
            } => Some(ValidatorVrfCommitData {
                target_epoch: *target_epoch,
                commitment: *commitment,
            }),
            _ => None,
        }
    }

    pub fn contribution_payload(&self) -> Option<ValidatorVrfContributionData> {
        match self {
            Self::Contribution {
                target_epoch,
                vrf_output,
                vrf_proof,
                ..
            } => Some(ValidatorVrfContributionData {
                target_epoch: *target_epoch,
                vrf_output: vrf_output.clone(),
                vrf_proof: vrf_proof.clone(),
            }),
            _ => None,
        }
    }

    fn commit_signable_bytes(
        validator: &Address,
        target_epoch: u64,
        commitment: &Hash256,
        public_key: &PublicKey,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(VALIDATOR_VRF_EVIDENCE_DOMAIN);
        bytes.push(ValidatorVrfEvidenceKind::Commit.rank());
        bytes.extend_from_slice(&target_epoch.to_le_bytes());
        bytes.extend_from_slice(&validator.0);
        bytes.extend_from_slice(commitment.as_bytes());
        bytes.extend_from_slice(public_key.as_bytes());
        bytes
    }

    fn contribution_signable_bytes(
        validator: &Address,
        target_epoch: u64,
        vrf_output: &[u8],
        vrf_proof: &[u8],
        public_key: &PublicKey,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(VALIDATOR_VRF_EVIDENCE_DOMAIN);
        bytes.push(ValidatorVrfEvidenceKind::Contribution.rank());
        bytes.extend_from_slice(&target_epoch.to_le_bytes());
        bytes.extend_from_slice(&validator.0);
        bytes.extend_from_slice(&(vrf_output.len() as u32).to_le_bytes());
        bytes.extend_from_slice(vrf_output);
        bytes.extend_from_slice(&(vrf_proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(vrf_proof);
        bytes.extend_from_slice(public_key.as_bytes());
        bytes
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ValidatorVrfEvidenceKey {
    pub target_epoch: u64,
    pub kind: ValidatorVrfEvidenceKind,
    pub validator: Address,
}

impl ValidatorUpdateData {
    pub fn validate(&self, num_partitions: u32) -> Result<()> {
        if self.executor_services.len() > MAX_VALIDATOR_EXECUTOR_SERVICES {
            return Err(ZinchaError::InvalidTransaction(format!(
                "Too many validator executor services: {} > {}",
                self.executor_services.len(),
                MAX_VALIDATOR_EXECUTOR_SERVICES
            )));
        }

        let mut seen_partitions = std::collections::HashSet::new();
        for service in &self.executor_services {
            if service.partition_id >= num_partitions {
                return Err(ZinchaError::InvalidTransaction(format!(
                    "Validator executor partition {} out of range for {} partitions",
                    service.partition_id, num_partitions
                )));
            }
            if service.rpc_endpoint.is_empty() {
                return Err(ZinchaError::InvalidTransaction(
                    "Validator executor endpoint cannot be empty".into(),
                ));
            }
            if service.rpc_endpoint.len() > MAX_VALIDATOR_EXECUTOR_ENDPOINT_BYTES {
                return Err(ZinchaError::InvalidTransaction(format!(
                    "Validator executor endpoint too long: {} > {}",
                    service.rpc_endpoint.len(),
                    MAX_VALIDATOR_EXECUTOR_ENDPOINT_BYTES
                )));
            }
            if !seen_partitions.insert(service.partition_id) {
                return Err(ZinchaError::InvalidTransaction(format!(
                    "Duplicate validator executor partition claim {}",
                    service.partition_id
                )));
            }
        }

        Ok(())
    }
}

pub fn validator_vrf_public_key_matches_address(
    validator: &Address,
    public_key: &PublicKey,
) -> bool {
    public_key.to_address() == *validator
}

impl ValidatorVrfCommitData {
    pub fn validate(&self) -> Result<()> {
        if self.commitment == Hash256::zero() {
            return Err(ZinchaError::InvalidTransaction(
                "Validator VRF commitment cannot be zero".into(),
            ));
        }
        Ok(())
    }
}

impl ValidatorVrfContributionData {
    pub fn validate(&self) -> Result<()> {
        if self.vrf_output.is_empty() {
            return Err(ZinchaError::InvalidTransaction(
                "Validator VRF output cannot be empty".into(),
            ));
        }
        if self.vrf_output.len() > MAX_VALIDATOR_VRF_OUTPUT_BYTES {
            return Err(ZinchaError::InvalidTransaction(format!(
                "Validator VRF output too long: {} > {}",
                self.vrf_output.len(),
                MAX_VALIDATOR_VRF_OUTPUT_BYTES
            )));
        }
        if self.vrf_proof.is_empty() {
            return Err(ZinchaError::InvalidTransaction(
                "Validator VRF proof cannot be empty".into(),
            ));
        }
        if self.vrf_proof.len() > MAX_VALIDATOR_VRF_PROOF_BYTES {
            return Err(ZinchaError::InvalidTransaction(format!(
                "Validator VRF proof too long: {} > {}",
                self.vrf_proof.len(),
                MAX_VALIDATOR_VRF_PROOF_BYTES
            )));
        }

        Ok(())
    }

    pub fn proof_signable_bytes(
        chain_id: &str,
        validator: &Address,
        target_epoch: u64,
        prior_seed: &Hash256,
    ) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            VALIDATOR_VRF_PROOF_DOMAIN.len() + chain_id.len() + validator.0.len() + 8 + 32,
        );
        bytes.extend_from_slice(VALIDATOR_VRF_PROOF_DOMAIN);
        bytes.extend_from_slice(chain_id.as_bytes());
        bytes.extend_from_slice(&validator.0);
        bytes.extend_from_slice(&target_epoch.to_le_bytes());
        bytes.extend_from_slice(prior_seed.as_bytes());
        bytes
    }

    pub fn commitment_hash(&self) -> Result<Hash256> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(
            VALIDATOR_VRF_COMMITMENT_DOMAIN.len()
                + 8
                + self.vrf_output.len()
                + 8
                + self.vrf_proof.len(),
        );
        bytes.extend_from_slice(VALIDATOR_VRF_COMMITMENT_DOMAIN);
        bytes.extend_from_slice(&(self.vrf_output.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.vrf_output);
        bytes.extend_from_slice(&(self.vrf_proof.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.vrf_proof);
        Ok(hash_bytes(&bytes))
    }

    pub fn expected_output_from_proof(
        public_key: &PublicKey,
        chain_id: &str,
        validator: &Address,
        target_epoch: u64,
        prior_seed: &Hash256,
        vrf_proof: &[u8],
    ) -> Result<Vec<u8>> {
        if vrf_proof.len() != 64 {
            return Err(ZinchaError::InvalidTransaction(format!(
                "Validator VRF proof must be 64 bytes, got {}",
                vrf_proof.len()
            )));
        }
        let mut proof_bytes = [0u8; 64];
        proof_bytes.copy_from_slice(vrf_proof);
        let proof = Signature::from_bytes(&proof_bytes)?;
        let mut output_preimage = Vec::with_capacity(
            VALIDATOR_VRF_OUTPUT_DOMAIN.len()
                + 32
                + chain_id.len()
                + validator.0.len()
                + 8
                + 32
                + 64,
        );
        output_preimage.extend_from_slice(VALIDATOR_VRF_OUTPUT_DOMAIN);
        output_preimage.extend_from_slice(public_key.as_bytes());
        output_preimage.extend_from_slice(chain_id.as_bytes());
        output_preimage.extend_from_slice(&validator.0);
        output_preimage.extend_from_slice(&target_epoch.to_le_bytes());
        output_preimage.extend_from_slice(prior_seed.as_bytes());
        output_preimage.extend_from_slice(&proof.to_bytes());
        Ok(hash_bytes(&output_preimage).as_bytes().to_vec())
    }

    pub fn verify_for_validator(
        &self,
        chain_id: &str,
        validator: &Address,
        public_key: &PublicKey,
        prior_seed: &Hash256,
    ) -> Result<()> {
        self.validate()?;
        if self.vrf_proof.len() != 64 {
            return Err(ZinchaError::InvalidTransaction(format!(
                "Validator VRF proof must be 64 bytes, got {}",
                self.vrf_proof.len()
            )));
        }
        let mut proof_bytes = [0u8; 64];
        proof_bytes.copy_from_slice(&self.vrf_proof);
        let proof = Signature::from_bytes(&proof_bytes)?;
        let signable =
            Self::proof_signable_bytes(chain_id, validator, self.target_epoch, prior_seed);
        public_key.verify(&signable, &proof)?;
        let expected_output = Self::expected_output_from_proof(
            public_key,
            chain_id,
            validator,
            self.target_epoch,
            prior_seed,
            &self.vrf_proof,
        )?;
        if self.vrf_output != expected_output {
            return Err(ZinchaError::InvalidTransaction(
                "Validator VRF output does not match the submitted proof".into(),
            ));
        }
        Ok(())
    }

    pub fn into_record(
        &self,
        validator: Address,
        commitment: Hash256,
        submitted_in_block: u64,
    ) -> ValidatorVrfContributionRecord {
        ValidatorVrfContributionRecord {
            validator,
            target_epoch: self.target_epoch,
            commitment,
            submitted_in_block,
            revealed_in_block: Some(submitted_in_block),
            vrf_output: self.vrf_output.clone(),
            vrf_proof: self.vrf_proof.clone(),
        }
    }
}

impl ValidatorVrfContributionRecord {
    pub fn committed_only(
        validator: Address,
        target_epoch: u64,
        commitment: Hash256,
        submitted_in_block: u64,
    ) -> Self {
        Self {
            validator,
            target_epoch,
            commitment,
            submitted_in_block,
            revealed_in_block: None,
            vrf_output: Vec::new(),
            vrf_proof: Vec::new(),
        }
    }

    pub fn is_revealed(&self) -> bool {
        self.revealed_in_block.is_some()
    }

    pub fn reveal(
        &mut self,
        data: &ValidatorVrfContributionData,
        revealed_in_block: u64,
    ) -> Result<()> {
        let commitment = data.commitment_hash()?;
        if commitment != self.commitment {
            return Err(ZinchaError::InvalidTransaction(
                "Validator VRF reveal does not match the committed hash".into(),
            ));
        }
        self.revealed_in_block = Some(revealed_in_block);
        self.vrf_output = data.vrf_output.clone();
        self.vrf_proof = data.vrf_proof.clone();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_validator_vrf_contribution_data_rejects_empty_fields() {
        let err = ValidatorVrfContributionData::default()
            .validate()
            .expect_err("empty contribution must fail");
        match err {
            ZinchaError::InvalidTransaction(msg) => {
                assert!(msg.contains("output"));
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_validator_vrf_contribution_data_accepts_bounded_payloads() {
        let data = ValidatorVrfContributionData {
            target_epoch: 7,
            vrf_output: vec![1; 32],
            vrf_proof: vec![2; 80],
        };
        data.validate().expect("bounded payload must validate");
    }

    #[test]
    fn test_validator_vrf_contribution_verifies_domain_bound_proof() {
        let vrf_key = Keypair::generate();
        let validator = vrf_key.address();
        let prior_seed = hash_bytes(b"prior-seed-a");
        let signable = ValidatorVrfContributionData::proof_signable_bytes(
            "test-chain",
            &validator,
            3,
            &prior_seed,
        );
        let proof = vrf_key.sign(&signable).to_bytes().to_vec();
        let output = ValidatorVrfContributionData::expected_output_from_proof(
            &vrf_key.public_key(),
            "test-chain",
            &validator,
            3,
            &prior_seed,
            &proof,
        )
        .expect("expected output");
        let data = ValidatorVrfContributionData {
            target_epoch: 3,
            vrf_output: output,
            vrf_proof: proof,
        };
        data.verify_for_validator("test-chain", &validator, &vrf_key.public_key(), &prior_seed)
            .expect("valid contribution proof");
    }

    #[test]
    fn test_validator_vrf_contribution_proof_depends_on_prior_seed() {
        let vrf_key = Keypair::generate();
        let validator = vrf_key.address();
        let prior_seed = hash_bytes(b"prior-seed-a");
        let other_seed = hash_bytes(b"prior-seed-b");
        let signable = ValidatorVrfContributionData::proof_signable_bytes(
            "test-chain",
            &validator,
            3,
            &prior_seed,
        );
        let proof = vrf_key.sign(&signable).to_bytes().to_vec();
        let output = ValidatorVrfContributionData::expected_output_from_proof(
            &vrf_key.public_key(),
            "test-chain",
            &validator,
            3,
            &prior_seed,
            &proof,
        )
        .expect("expected output");
        let data = ValidatorVrfContributionData {
            target_epoch: 3,
            vrf_output: output,
            vrf_proof: proof,
        };
        let err = data
            .verify_for_validator("test-chain", &validator, &vrf_key.public_key(), &other_seed)
            .expect_err("wrong prior seed must fail");
        assert!(
            err.to_string().contains("signature"),
            "expected signature mismatch, got {err}",
        );
    }

    #[test]
    fn test_validator_vrf_commit_rejects_zero_commitment() {
        let err = ValidatorVrfCommitData::default()
            .validate()
            .expect_err("zero commitment must fail");
        match err {
            ZinchaError::InvalidTransaction(msg) => assert!(msg.contains("commitment")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn test_validator_vrf_contribution_commitment_hash_round_trip() {
        let vrf_key = Keypair::generate();
        let validator = vrf_key.address();
        let prior_seed = hash_bytes(b"prior-seed-a");
        let signable = ValidatorVrfContributionData::proof_signable_bytes(
            "test-chain",
            &validator,
            3,
            &prior_seed,
        );
        let proof = vrf_key.sign(&signable).to_bytes().to_vec();
        let output = ValidatorVrfContributionData::expected_output_from_proof(
            &vrf_key.public_key(),
            "test-chain",
            &validator,
            3,
            &prior_seed,
            &proof,
        )
        .expect("expected output");
        let data = ValidatorVrfContributionData {
            target_epoch: 3,
            vrf_output: output,
            vrf_proof: proof,
        };
        let commitment = data.commitment_hash().expect("commitment");
        let mut record =
            ValidatorVrfContributionRecord::committed_only(validator, 3, commitment, 11);
        record
            .reveal(&data, 12)
            .expect("reveal must match commitment");
        assert!(record.is_revealed());
        assert_eq!(record.revealed_in_block, Some(12));
    }
}
