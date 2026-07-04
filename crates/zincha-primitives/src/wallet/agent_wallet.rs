use crate::crypto::{Address, Hash256, Keypair, PublicKey, Signature};
use crate::error::{Result, ZinchaError};
use crate::primitives::agent::{AgentRegisterData, AgentUpdateData, ReputationUpdateData};
use crate::primitives::agreement::{
    AgreementAcceptData, AgreementCancelData, AgreementCreateData, AgreementDisputeData,
    AgreementDisputeReputationEffect, AgreementExecuteData, AgreementPayoutShare,
    AgreementResolveData, MilestoneDef,
};
use crate::primitives::task::{
    TaskAcceptData, TaskDisputeData, TaskFinalizeData, TaskFulfillData, TaskResolveData,
    TaskSubmitData,
};
use crate::primitives::tool::ToolInvokeData;
use crate::primitives::*;

/// Signing backend for wallet-built transactions.
pub trait TransactionSigner: Send + Sync {
    fn public_key(&self) -> PublicKey;
    fn sign_transaction(&self, tx: &Transaction, tx_hash: &Hash256) -> Result<Signature>;
}

impl TransactionSigner for Keypair {
    fn public_key(&self) -> PublicKey {
        Keypair::public_key(self)
    }

    fn sign_transaction(&self, _tx: &Transaction, tx_hash: &Hash256) -> Result<Signature> {
        Ok(Keypair::sign(self, tx_hash.as_bytes()))
    }
}

impl<T> TransactionSigner for Box<T>
where
    T: TransactionSigner + ?Sized,
{
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }

    fn sign_transaction(&self, tx: &Transaction, tx_hash: &Hash256) -> Result<Signature> {
        (**self).sign_transaction(tx, tx_hash)
    }
}

/// High-level wallet interface for AI agents to interact with the Zincha chain.
///
/// The `AgentWallet` wraps a signing backend and provides ergonomic methods for
/// building, signing, and submitting all Zincha transaction types.
///
/// # Example
/// ```rust,no_run
/// use zincha_primitives::crypto::{Address, Hash256, Keypair};
/// use zincha_primitives::primitives::Capability;
/// use zincha_primitives::wallet::AgentWallet;
///
/// let keypair = Keypair::generate();
/// let mut wallet = AgentWallet::new(keypair, "zincha-altair-1", "http://localhost:9944");
///
/// // Register as an agent
/// let capabilities = vec![Capability::new("ai.analysis")];
/// let model_hash = Hash256::zero();
/// let fee = 500_000;
/// let _tx = wallet
///     .build_register_agent(
///         "MyAgent-7B",
///         "A specialist agent",
///         capabilities.clone(),
///         model_hash,
///         fee,
///     )
///     .unwrap();
///
/// // Submit a task
/// let max_fee = 10_000;
/// let deadline_ms = 1_900_000_000_000;
/// let _tx = wallet
///     .build_submit_task(
///         "Analyze market data",
///         capabilities,
///         max_fee,
///         1,
///         deadline_ms,
///         Vec::new(),
///         fee,
///     )
///     .unwrap();
///
/// // Transfer tokens
/// let recipient = Address::zero();
/// let amount = 100;
/// let _tx = wallet.build_transfer(recipient, amount, fee).unwrap();
/// ```
pub struct AgentWallet {
    signer: Box<dyn TransactionSigner>,
    chain_id: String,
    nonce: u64,
    /// RPC endpoint (for future HTTP client integration).
    #[allow(dead_code)]
    rpc_endpoint: String,
    /// Optional embedding service URL (e.g. "http://localhost:8090").
    /// When set, embeddings are fetched from this service instead of
    /// using the built-in deterministic hasher.
    embed_url: Option<String>,
    tx_validity_window: Option<(u64, Hash256, u64)>,
    timestamp_ms: Option<u64>,
}

impl AgentWallet {
    fn signer_public_key(&self) -> PublicKey {
        self.signer.public_key()
    }

    fn sign_transaction(&self, mut tx: Transaction) -> Result<SignedTransaction> {
        if !tx.has_explicit_validity_window() {
            if let Some((reference_height, reference_hash, ttl_blocks)) = self.tx_validity_window {
                tx.set_validity_window(reference_height, reference_hash, ttl_blocks);
            }
        }
        let public_key = self.signer_public_key();
        let expected_sender = public_key.to_address();
        if tx.sender != expected_sender {
            return Err(ZinchaError::InvalidTransaction(format!(
                "Transaction sender {} does not match signer address {}",
                tx.sender, expected_sender
            )));
        }

        let tx_hash = tx.hash();
        let signature = self.signer.sign_transaction(&tx, &tx_hash)?;
        let signed_tx = SignedTransaction {
            transaction: tx,
            signature,
            public_key,
            hash: tx_hash,
        };
        signed_tx.verify()?;
        Ok(signed_tx)
    }

    fn ensure_vrf_public_key_matches_signer(&self, vrf_public_key: &PublicKey) -> Result<()> {
        if vrf_public_key.as_bytes() != self.signer_public_key().as_bytes() {
            return Err(ZinchaError::InvalidTransaction(
                "Validator vrf_public_key must match the wallet signing public key".into(),
            ));
        }
        Ok(())
    }

    fn ensure_vrf_keypair_matches_signer(&self, vrf_keypair: &Keypair) -> Result<()> {
        self.ensure_vrf_public_key_matches_signer(&vrf_keypair.public_key())
    }

    /// Create a new wallet from a keypair.
    pub fn new(keypair: Keypair, chain_id: &str, rpc_endpoint: &str) -> Self {
        Self::from_signer(keypair, chain_id, rpc_endpoint)
    }

    /// Create a new wallet from an arbitrary signing backend.
    pub fn from_signer<S>(signer: S, chain_id: &str, rpc_endpoint: &str) -> Self
    where
        S: TransactionSigner + 'static,
    {
        Self {
            signer: Box::new(signer),
            chain_id: chain_id.to_string(),
            nonce: 0,
            rpc_endpoint: rpc_endpoint.to_string(),
            embed_url: None,
            tx_validity_window: None,
            timestamp_ms: None,
        }
    }

    /// Create a wallet with a freshly generated keypair.
    pub fn generate(chain_id: &str, rpc_endpoint: &str) -> Self {
        Self::new(Keypair::generate(), chain_id, rpc_endpoint)
    }

    /// Create a wallet from a secret key.
    pub fn from_secret(secret: &[u8; 32], chain_id: &str, rpc_endpoint: &str) -> Self {
        Self::new(Keypair::from_secret_bytes(secret), chain_id, rpc_endpoint)
    }

    /// Set the embedding service URL used for optional client neural embeddings.
    ///
    /// When configured, registration / task / tool builders will try to attach
    /// a neural embedding from this service. When not configured, builders omit
    /// the neural embedding entirely and rely on the protocol's verified
    /// deterministic embedding.
    ///
    /// ```rust
    /// use zincha_primitives::wallet::AgentWallet;
    ///
    /// let mut wallet = AgentWallet::generate("zincha-altair-1", "http://localhost:9944");
    /// wallet.set_embed_url("http://localhost:8090");
    /// ```
    pub fn set_embed_url(&mut self, url: &str) {
        self.embed_url = Some(url.to_string());
    }

    pub fn set_transaction_validity_window(
        &mut self,
        reference_block_height: u64,
        reference_block_hash: Hash256,
        ttl_blocks: u64,
    ) {
        self.tx_validity_window = Some((
            reference_block_height,
            reference_block_hash,
            ttl_blocks.max(1),
        ));
    }

    /// Override the timestamp used by subsequently built transactions.
    pub fn set_timestamp_ms(&mut self, timestamp_ms: u64) {
        self.timestamp_ms = Some(timestamp_ms);
    }

    /// Clear any deterministic timestamp override.
    pub fn clear_timestamp_ms(&mut self) {
        self.timestamp_ms = None;
    }

    /// Compute the deterministic protocol embedding for the given text.
    ///
    /// This returns the same built-in embedding family validators compute for the
    /// verified semantic signal. Wallet builders do not serialize this as a
    /// neural embedding.
    pub fn compute_embedding(&self, text: &str) -> Vec<f32> {
        if let Some(ref url) = self.embed_url {
            match self.fetch_embedding(url, text) {
                Ok(vec) => return vec,
                Err(e) => {
                    eprintln!("Embed service error (falling back to built-in): {}", e);
                }
            }
        }
        // Fallback: built-in deterministic hasher
        crate::embedding::embed_text(text).0
    }

    /// Compute an optional client neural embedding for the given text.
    ///
    /// Returns `None` unless an embedding service is explicitly configured.
    /// Service failures are logged and treated as "no neural embedding" rather
    /// than falling back to the deterministic protocol embedding.
    pub fn compute_neural_embedding(&self, text: &str) -> Option<Vec<f32>> {
        let url = self.embed_url.as_ref()?;
        match self.fetch_embedding(url, text) {
            Ok(vec) => Some(vec),
            Err(e) => {
                eprintln!("Embed service error (omitting neural embedding): {}", e);
                None
            }
        }
    }

    /// Whether this wallet has an external client neural-embedding service configured.
    pub fn has_neural_embedding_service(&self) -> bool {
        self.embed_url.is_some()
    }

    /// Compute a client neural embedding for the given text, but fail if the
    /// external embedding service is unavailable or misconfigured.
    pub fn compute_neural_embedding_strict(&self, text: &str) -> Result<Vec<f32>> {
        let url = self.embed_url.as_ref().ok_or_else(|| {
            ZinchaError::InvalidTransaction(
                "client neural embeddings require an embed service URL".into(),
            )
        })?;
        self.fetch_embedding(url, text).map_err(|error| {
            ZinchaError::InvalidTransaction(format!("compute client neural embedding: {}", error))
        })
    }

    fn agent_semantic_profile_text(
        name: &str,
        description: &str,
        capabilities: &[Capability],
    ) -> String {
        format!(
            "{} {} {}",
            name,
            description,
            capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )
    }

    /// Compute a client neural embedding for an agent semantic profile.
    pub fn compute_agent_neural_embedding(
        &self,
        name: &str,
        description: &str,
        capabilities: &[Capability],
    ) -> Option<Vec<f32>> {
        self.compute_neural_embedding(&Self::agent_semantic_profile_text(
            name,
            description,
            capabilities,
        ))
    }

    /// Compute a client neural embedding for an agent semantic profile and
    /// error if the external embedding service is unavailable.
    pub fn compute_agent_neural_embedding_strict(
        &self,
        name: &str,
        description: &str,
        capabilities: &[Capability],
    ) -> Result<Vec<f32>> {
        self.compute_neural_embedding_strict(&Self::agent_semantic_profile_text(
            name,
            description,
            capabilities,
        ))
    }

    /// Call the embedding microservice via curl.
    fn fetch_embedding(&self, url: &str, text: &str) -> std::result::Result<Vec<f32>, String> {
        let endpoint = format!("{}/embed", url);
        let payload = serde_json::json!({"text": text}).to_string();
        let output = std::process::Command::new("curl")
            .args([
                "-s",
                "--max-time",
                "10",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                &payload,
                &endpoint,
            ])
            .output()
            .map_err(|e| format!("curl failed: {}", e))?;
        let body = String::from_utf8_lossy(&output.stdout);
        if body.is_empty() {
            return Err("Empty response from embed service".into());
        }
        let json: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| format!("JSON parse error: {}", e))?;
        let arr = json["embedding"]
            .as_array()
            .ok_or("No 'embedding' field in response")?;
        let vec: Vec<f32> = arr
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();
        if vec.is_empty() {
            return Err("Empty embedding vector".into());
        }
        Ok(vec)
    }

    /// Get the wallet's address.
    pub fn address(&self) -> Address {
        self.signer_public_key().to_address()
    }

    /// Get the public key hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signer_public_key().as_bytes())
    }

    /// Set the nonce (should be fetched from chain state).
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    /// Get current nonce and auto-increment.
    fn next_nonce(&mut self) -> u64 {
        let n = self.nonce;
        self.nonce += 1;
        n
    }

    /// Current timestamp in milliseconds.
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn transaction_timestamp_ms(&self) -> u64 {
        self.timestamp_ms.unwrap_or_else(Self::now_ms)
    }

    // -----------------------------------------------------------------------
    // Transaction builders
    // -----------------------------------------------------------------------

    /// Build and sign a transfer transaction.
    pub fn build_transfer(
        &mut self,
        recipient: Address,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::Transfer,
            sender: self.address(),
            recipient,
            amount,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an entity-link transaction.
    pub fn build_entity_link(
        &mut self,
        entity: Address,
        authorizer: &Keypair,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let message = crate::primitives::entity::entity_link_message(
            &self.chain_id,
            &self.address(),
            &entity,
        );
        let data = crate::primitives::EntityLinkData {
            entity,
            authorizer_public_key: Some(authorizer.public_key()),
            authorizer_signature: Some(authorizer.sign(&message)),
        };
        let tx = Transaction {
            tx_type: TxType::EntityLink,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a transfer transaction with an explicit EIP-1559
    /// max-priority-fee-per-gas tip.
    pub fn build_transfer_with_priority_fee(
        &mut self,
        recipient: Address,
        amount: u64,
        fee: u64,
        max_priority_fee_per_gas: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::Transfer,
            sender: self.address(),
            recipient,
            amount,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agent registration transaction.
    ///
    /// The `description` is a natural-language summary of what this agent does.
    /// An embedding vector is computed automatically for Layer 2 semantic matching.
    pub fn build_register_agent(
        &mut self,
        name: &str,
        description: &str,
        capabilities: Vec<Capability>,
        model_hash: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_register_agent_full(name, description, capabilities, model_hash, 0, vec![], fee)
    }

    /// Build and sign an agent registration transaction with pricing.
    ///
    /// `min_fee`: Minimum fee (micro-ZIN) this agent will accept. Tasks
    /// with max_fee below this are filtered out during matching. 0 = any.
    ///
    /// `fee_schedule`: Per-capability pricing. e.g.,
    /// `vec![("ai.reasoning".into(), 5_000_000), ("ai.coding".into(), 10_000_000)]`
    pub fn build_register_agent_full(
        &mut self,
        name: &str,
        description: &str,
        capabilities: Vec<Capability>,
        model_hash: Hash256,
        min_fee: u64,
        fee_schedule: Vec<(String, u64)>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        // Attach a neural embedding only when an external embed service is configured.
        let neural_embedding =
            self.compute_agent_neural_embedding(name, description, &capabilities);

        let data = AgentRegisterData {
            name: name.to_string(),
            description: description.to_string(),
            neural_embedding,
            model_hash,
            capabilities,
            metadata: vec![],
            min_fee,
            fee_schedule,
        };

        let tx = Transaction {
            tx_type: TxType::AgentRegister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an task submission transaction.
    ///
    /// The `description` is embedded automatically for Layer 2 semantic matching.
    pub fn build_submit_task(
        &mut self,
        description: &str,
        required_capabilities: Vec<Capability>,
        max_fee: u64,
        priority: u8,
        deadline_ms: u64,
        parameters: Vec<u8>,
        tx_fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_submit_task_with_prefs(
            description,
            required_capabilities,
            max_fee,
            priority,
            deadline_ms,
            parameters,
            tx_fee,
            crate::primitives::task::MatchPreferences::default(),
        )
    }

    /// Build and sign an task submission with custom matching preferences.
    pub fn build_submit_task_with_prefs(
        &mut self,
        description: &str,
        required_capabilities: Vec<Capability>,
        max_fee: u64,
        priority: u8,
        deadline_ms: u64,
        parameters: Vec<u8>,
        tx_fee: u64,
        match_preferences: crate::primitives::task::MatchPreferences,
    ) -> Result<SignedTransaction> {
        let embed_text = format!(
            "{} {}",
            description,
            required_capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let neural_embedding = self.compute_neural_embedding(&embed_text);

        let data = TaskSubmitData {
            description: description.to_string(),
            neural_embedding,
            required_capabilities,
            max_fee,
            priority,
            deadline: deadline_ms,
            parameters,
            match_preferences,
        };

        let tx = Transaction {
            tx_type: TxType::TaskSubmit,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee: tx_fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a validator registration transaction.
    pub fn build_register_validator(&mut self, stake: u64, fee: u64) -> Result<SignedTransaction> {
        self.build_register_validator_with_update(
            stake,
            ValidatorUpdateData {
                executor_services: vec![],
                vrf_public_key: Some(self.signer_public_key()),
            },
            fee,
        )
    }

    /// Build and sign a validator registration transaction with metadata.
    pub fn build_register_validator_with_update(
        &mut self,
        stake: u64,
        mut update: ValidatorUpdateData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        if update.vrf_public_key.is_none() {
            update.vrf_public_key = Some(self.signer_public_key());
        }
        if let Some(vrf_public_key) = update.vrf_public_key.as_ref() {
            self.ensure_vrf_public_key_matches_signer(vrf_public_key)?;
        }
        let tx = Transaction {
            tx_type: TxType::ValidatorRegister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: stake,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: if update.executor_services.is_empty() && update.vrf_public_key.is_none() {
                vec![]
            } else {
                bincode::serialize(&update)?
            },
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a validator registration transaction with an explicit VRF key.
    ///
    /// The VRF key must match this wallet's signing key.
    pub fn build_register_validator_with_vrf_public_key(
        &mut self,
        stake: u64,
        vrf_public_key: PublicKey,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_register_validator_with_update(
            stake,
            ValidatorUpdateData {
                executor_services: vec![],
                vrf_public_key: Some(vrf_public_key),
            },
            fee,
        )
    }

    /// Build and sign a validator metadata update transaction.
    pub fn build_update_validator(
        &mut self,
        update: ValidatorUpdateData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ValidatorUpdate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&update)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a validator metadata update that only publishes the wallet's VRF key.
    ///
    /// The VRF key must match this wallet's signing key. The chain will reject
    /// attempts to rotate away from an already-published key.
    pub fn build_update_validator_vrf_public_key(
        &mut self,
        vrf_public_key: PublicKey,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.ensure_vrf_public_key_matches_signer(&vrf_public_key)?;
        self.build_update_validator(
            ValidatorUpdateData {
                executor_services: vec![],
                vrf_public_key: Some(vrf_public_key),
            },
            fee,
        )
    }

    /// Build and sign a validator VRF commit transaction.
    pub fn build_validator_vrf_commit(
        &mut self,
        target_epoch: u64,
        prior_seed: &Hash256,
        vrf_keypair: &Keypair,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let reveal = self.build_validator_vrf_reveal_data(target_epoch, prior_seed, vrf_keypair)?;
        let tx = Transaction {
            tx_type: TxType::ValidatorVrfCommit,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&ValidatorVrfCommitData {
                target_epoch,
                commitment: reveal.commitment_hash()?,
            })?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    fn build_validator_vrf_reveal_data(
        &self,
        target_epoch: u64,
        prior_seed: &Hash256,
        vrf_keypair: &Keypair,
    ) -> Result<ValidatorVrfContributionData> {
        self.ensure_vrf_keypair_matches_signer(vrf_keypair)?;
        let signable = ValidatorVrfContributionData::proof_signable_bytes(
            &self.chain_id,
            &self.address(),
            target_epoch,
            prior_seed,
        );
        let proof = vrf_keypair.sign(&signable).to_bytes().to_vec();
        let output = ValidatorVrfContributionData::expected_output_from_proof(
            &vrf_keypair.public_key(),
            &self.chain_id,
            &self.address(),
            target_epoch,
            prior_seed,
            &proof,
        )?;
        Ok(ValidatorVrfContributionData {
            target_epoch,
            vrf_output: output,
            vrf_proof: proof,
        })
    }

    /// Build and sign a validator VRF reveal transaction.
    pub fn build_validator_vrf_contribution(
        &mut self,
        target_epoch: u64,
        prior_seed: &Hash256,
        vrf_keypair: &Keypair,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let reveal = self.build_validator_vrf_reveal_data(target_epoch, prior_seed, vrf_keypair)?;
        let tx = Transaction {
            tx_type: TxType::ValidatorVrfContribution,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&reveal)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agreement creation transaction with canonical N-way
    /// settlement semantics.
    pub fn build_create_agreement(
        &mut self,
        parties: Vec<Address>,
        terms: Vec<u8>,
        escrow_amount: u64,
        expires_at: u64,
        arbitrator: Option<Address>,
        milestones: Vec<MilestoneDef>,
        service_provider: Address,
        settlement_allocations: Vec<AgreementPayoutShare>,
        settlement_approver: Option<Address>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let milestones = if milestones.is_empty() {
            crate::primitives::agreement::canonical_single_payment_milestones(escrow_amount)
        } else {
            milestones
        };
        let data = AgreementCreateData {
            parties,
            terms,
            escrow_amount,
            expires_at,
            arbitrator,
            milestones,
            service_provider,
            settlement_allocations,
            settlement_approver,
        };

        let tx = Transaction {
            tx_type: TxType::AgreementCreate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: escrow_amount,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a tool registration transaction.
    pub fn build_register_tool(
        &mut self,
        name: &str,
        description: &str,
        endpoint: &str,
        price_per_call: u64,
        capabilities: Vec<Capability>,
        version: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_register_tool_with_settlement(
            name,
            description,
            endpoint,
            price_per_call,
            HttpToolSettlementMode::PrepaidAccess,
            3_600_000,
            900_000,
            4_096,
            ToolArbitrationPolicy::Protocol,
            capabilities,
            version,
            fee,
        )
    }

    /// Build and sign a result-escrowed HTTP tool registration transaction.
    pub fn build_register_tool_result_escrowed(
        &mut self,
        name: &str,
        description: &str,
        endpoint: &str,
        price_per_call: u64,
        sla_ms: u64,
        challenge_window_ms: u64,
        max_result_metadata_bytes: u32,
        capabilities: Vec<Capability>,
        version: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_register_tool_with_settlement(
            name,
            description,
            endpoint,
            price_per_call,
            HttpToolSettlementMode::ResultEscrowed,
            sla_ms,
            challenge_window_ms,
            max_result_metadata_bytes,
            ToolArbitrationPolicy::Protocol,
            capabilities,
            version,
            fee,
        )
    }

    /// Build and sign a milestone-escrowed HTTP tool registration transaction.
    pub fn build_register_tool_milestone_escrowed(
        &mut self,
        name: &str,
        description: &str,
        endpoint: &str,
        price_per_call: u64,
        sla_ms: u64,
        challenge_window_ms: u64,
        max_result_metadata_bytes: u32,
        capabilities: Vec<Capability>,
        version: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_register_tool_with_settlement(
            name,
            description,
            endpoint,
            price_per_call,
            HttpToolSettlementMode::MilestoneEscrowed,
            sla_ms,
            challenge_window_ms,
            max_result_metadata_bytes,
            ToolArbitrationPolicy::Protocol,
            capabilities,
            version,
            fee,
        )
    }

    /// Build and sign a metered-usage HTTP tool registration transaction.
    ///
    /// In this mode `price_per_call` is interpreted as the per-unit rate, and
    /// callers must supply `max_metered_units` at invoke time.
    pub fn build_register_tool_metered_usage(
        &mut self,
        name: &str,
        description: &str,
        endpoint: &str,
        price_per_unit: u64,
        sla_ms: u64,
        challenge_window_ms: u64,
        max_result_metadata_bytes: u32,
        capabilities: Vec<Capability>,
        version: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_register_tool_with_settlement(
            name,
            description,
            endpoint,
            price_per_unit,
            HttpToolSettlementMode::MeteredUsage,
            sla_ms,
            challenge_window_ms,
            max_result_metadata_bytes,
            ToolArbitrationPolicy::Protocol,
            capabilities,
            version,
            fee,
        )
    }

    /// Build and sign a tool registration transaction with explicit settlement settings.
    pub fn build_register_tool_with_settlement(
        &mut self,
        name: &str,
        description: &str,
        endpoint: &str,
        price_per_call: u64,
        settlement_mode: HttpToolSettlementMode,
        sla_ms: u64,
        challenge_window_ms: u64,
        max_result_metadata_bytes: u32,
        arbitration_policy: ToolArbitrationPolicy,
        capabilities: Vec<Capability>,
        version: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        use crate::primitives::ToolRegisterData;

        // Attach a neural embedding only when an external embed service is configured.
        let embed_text = format!(
            "{} {} {}",
            name,
            description,
            capabilities
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let neural_embedding = self.compute_neural_embedding(&embed_text);

        let data = ToolRegisterData {
            name: name.to_string(),
            description: description.to_string(),
            endpoint: endpoint.to_string(),
            price_per_call,
            settlement_mode,
            sla_ms,
            challenge_window_ms,
            max_result_metadata_bytes,
            arbitration_policy,
            capabilities,
            match_enabled: true,
            neural_embedding,
            version: version.to_string(),
        };

        let tx = Transaction {
            tx_type: TxType::ToolRegister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription plan creation transaction for a tool.
    pub fn build_create_tool_subscription_plan(
        &mut self,
        tool_id: Hash256,
        name: &str,
        price_per_period: u64,
        period_ms: u64,
        included_calls: u32,
        included_credits: u64,
        overage_policy: crate::primitives::tool::SubscriptionOveragePolicy,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolSubscriptionPlanCreateData {
            tool_id,
            name: name.to_string(),
            price_per_period,
            period_ms,
            included_calls,
            included_credits,
            overage_policy,
        };
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionPlanCreate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription plan update transaction.
    pub fn build_update_tool_subscription_plan(
        &mut self,
        update: crate::primitives::tool::ToolSubscriptionPlanUpdateData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionPlanUpdate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&update)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription start transaction.
    pub fn build_start_tool_subscription(
        &mut self,
        plan_id: Hash256,
        reserve_amount: u64,
        auto_renew: bool,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolSubscriptionStartData {
            plan_id,
            reserve_amount,
            auto_renew,
        };
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionStart,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription reserve top-up transaction.
    pub fn build_top_up_tool_subscription(
        &mut self,
        subscription_id: Hash256,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolSubscriptionTopUpData {
            subscription_id,
            amount,
        };
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionTopUp,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription cancel transaction.
    pub fn build_cancel_tool_subscription(
        &mut self,
        subscription_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolSubscriptionCancelData { subscription_id };
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionCancel,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription resume transaction.
    pub fn build_resume_tool_subscription(
        &mut self,
        subscription_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_resume_tool_subscription_with_reserve(subscription_id, 0, fee)
    }

    /// Build and sign a subscription resume transaction with optional reserve funding.
    pub fn build_resume_tool_subscription_with_reserve(
        &mut self,
        subscription_id: Hash256,
        reserve_amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolSubscriptionResumeData {
            subscription_id,
            reserve_amount,
        };
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionResume,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a subscription renewal transaction.
    pub fn build_renew_tool_subscription(
        &mut self,
        subscription_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolSubscriptionRenewData { subscription_id };
        let tx = Transaction {
            tx_type: TxType::ToolSubscriptionRenew,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a staking transaction.
    pub fn build_stake(
        &mut self,
        amount: u64,
        target: StakeTarget,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::Stake,
            sender: self.address(),
            recipient: Address::zero(),
            amount,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&target)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a requester auto-match bond transaction.
    pub fn build_requester_auto_match_bond(
        &mut self,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::Stake,
            sender: self.address(),
            recipient: Address::zero(),
            amount,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&crate::primitives::StakeTarget::RequesterAutoMatch)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an unstaking transaction.
    pub fn build_unstake(
        &mut self,
        amount: u64,
        target: StakeTarget,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::Unstake,
            sender: self.address(),
            recipient: Address::zero(),
            amount,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&target)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a validator exit transaction (full unstake).
    pub fn build_exit_validator(&mut self, fee: u64) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ValidatorExit,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an task fulfillment transaction.
    pub fn build_fulfill_task(
        &mut self,
        task_id: Hash256,
        result_hash: Hash256,
        result_data: Vec<u8>,
        tools_used: Vec<Hash256>,
        input_refs: Vec<Hash256>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = TaskFulfillData {
            task_id,
            result_hash,
            result_data,
            tools_used,
            input_refs,
            receipt_proofs: vec![],
        };
        let tx = Transaction {
            tx_type: TxType::TaskFulfill,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an task fulfillment with verified tool invocations.
    ///
    /// `receipt_proofs` is a list of `ReceiptWithProof` entries obtained via
    /// `GET /v1/tool-receipt/:token_id`. Each contains an AccessTokenReceipt
    /// (issuance facts) plus a Merkle inclusion proof against the block
    /// header's `tool_receipt_root`. Receipts survive access token pruning.
    /// Only verified tools receive quality propagation in subsequent
    /// ReputationUpdate ratings.
    pub fn build_fulfill_task_verified(
        &mut self,
        task_id: Hash256,
        result_hash: Hash256,
        result_data: Vec<u8>,
        tools_used: Vec<Hash256>,
        input_refs: Vec<Hash256>,
        receipt_proofs: Vec<crate::primitives::tool::ReceiptWithProof>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = TaskFulfillData {
            task_id,
            result_hash,
            result_data,
            tools_used,
            input_refs,
            receipt_proofs,
        };
        let tx = Transaction {
            tx_type: TxType::TaskFulfill,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester acceptance for a submitted task result.
    pub fn build_accept_task(&mut self, task_id: Hash256, fee: u64) -> Result<SignedTransaction> {
        let data = TaskAcceptData { task_id };
        let tx = Transaction {
            tx_type: TxType::TaskAccept,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester dispute for a submitted task result.
    pub fn build_dispute_task(
        &mut self,
        task_id: Hash256,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = TaskDisputeData {
            task_id,
            reason: reason.to_string(),
        };
        let tx = Transaction {
            tx_type: TxType::TaskDispute,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign arbitrator resolution for a disputed task result.
    pub fn build_resolve_task(
        &mut self,
        task_id: Hash256,
        agent_wins: bool,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = TaskResolveData {
            task_id,
            agent_wins,
            reason: reason.to_string(),
        };
        let tx = Transaction {
            tx_type: TxType::TaskResolve,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign agent finalization after an uncontested challenge window.
    pub fn build_finalize_task(&mut self, task_id: Hash256, fee: u64) -> Result<SignedTransaction> {
        let data = TaskFinalizeData { task_id };
        let tx = Transaction {
            tx_type: TxType::TaskFinalize,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an task cancellation transaction.
    pub fn build_cancel_task(&mut self, task_id: Hash256, fee: u64) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::TaskCancel,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: task_id.as_bytes().to_vec(),
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an task decomposition transaction.
    ///
    /// Breaks a pending task into subtasks, each matched and fulfilled independently.
    /// Subtasks form a DAG via dependency indices — `dependencies: [0, 1]` means
    /// "this subtask requires subtasks 0 and 1 to complete first."
    pub fn build_decompose_task(
        &mut self,
        task_id: Hash256,
        subtasks: Vec<SubTaskDef>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        use crate::primitives::task::TaskDecomposeData;
        let data = TaskDecomposeData { task_id, subtasks };
        let tx = Transaction {
            tx_type: TxType::TaskDecompose,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a batch transaction containing multiple operations.
    ///
    /// All operations execute atomically in a single block — one nonce,
    /// one fee, all-or-nothing. Max 16 operations per batch.
    ///
    /// ```rust,no_run
    /// use zincha_primitives::crypto::{Address, Keypair};
    /// use zincha_primitives::primitives::{BatchOperation, TxType};
    /// use zincha_primitives::wallet::AgentWallet;
    ///
    /// let mut wallet = AgentWallet::new(
    ///     Keypair::generate(),
    ///     "zincha-altair-1",
    ///     "http://localhost:9944",
    /// );
    /// let batch = wallet.build_batch(vec![
    ///     BatchOperation {
    ///         tx_type: TxType::Transfer,
    ///         recipient: Address::zero(),
    ///         amount: 1,
    ///         data: Vec::new(),
    ///     },
    ///     BatchOperation {
    ///         tx_type: TxType::Transfer,
    ///         recipient: Address::zero(),
    ///         amount: 2,
    ///         data: Vec::new(),
    ///     },
    /// ], 200).unwrap();
    /// ```
    pub fn build_batch(
        &mut self,
        operations: Vec<BatchOperation>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        if operations.is_empty() {
            return Err(ZinchaError::InvalidTransaction(
                "Batch must contain at least one operation".into(),
            ));
        }
        if operations.len() > 16 {
            return Err(ZinchaError::InvalidTransaction(
                "Max 16 operations per batch".into(),
            ));
        }
        let data = BatchData { operations };
        let tx = Transaction {
            tx_type: TxType::Batch,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agent update transaction.
    pub fn build_update_agent(
        &mut self,
        name: Option<String>,
        description: Option<String>,
        model_hash: Option<Hash256>,
        capabilities: Option<Vec<Capability>>,
        metadata: Option<Vec<u8>>,
        active: Option<bool>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_update_agent_full(
            name,
            description,
            None,
            model_hash,
            capabilities,
            metadata,
            active,
            None,
            None,
            fee,
        )
    }

    /// Build and sign an agent update transaction with explicit client neural
    /// embedding control and pricing fields.
    pub fn build_update_agent_full(
        &mut self,
        name: Option<String>,
        description: Option<String>,
        neural_embedding: Option<Vec<f32>>,
        model_hash: Option<Hash256>,
        capabilities: Option<Vec<Capability>>,
        metadata: Option<Vec<u8>>,
        active: Option<bool>,
        min_fee: Option<u64>,
        fee_schedule: Option<Vec<(String, u64)>>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let semantic_update = name.is_some() || description.is_some() || capabilities.is_some();
        let neural_embedding = match neural_embedding {
            Some(embedding) => Some(embedding),
            None if !semantic_update => None,
            None => match (&name, &description, &capabilities) {
                (Some(name), Some(description), Some(capabilities)) => self
                    .compute_agent_neural_embedding(name, description, capabilities)
                    .or_else(|| Some(Vec::new())),
                _ => Some(Vec::new()),
            },
        };
        let data = AgentUpdateData {
            name,
            description,
            neural_embedding,
            model_hash,
            capabilities,
            metadata,
            active,
            min_fee,
            fee_schedule,
        };
        let tx = Transaction {
            tx_type: TxType::AgentUpdate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a reputation update transaction.
    pub fn build_update_reputation(
        &mut self,
        task_id: Hash256,
        quality_score: f64,
        requester_accepted: bool,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_update_reputation_with_feedback(
            task_id,
            quality_score,
            requester_accepted,
            "",
            fee,
        )
    }

    /// Build a reputation update with qualitative text feedback.
    pub fn build_update_reputation_with_feedback(
        &mut self,
        task_id: Hash256,
        quality_score: f64,
        requester_accepted: bool,
        feedback: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ReputationUpdateData {
            task_id,
            quality_score,
            requester_accepted,
            feedback: feedback.chars().take(500).collect(),
        };
        data.validate().map_err(ZinchaError::InvalidTransaction)?;
        let tx = Transaction {
            tx_type: TxType::ReputationUpdate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a prepaid tool access purchase.
    pub fn build_purchase_tool_access(
        &mut self,
        tool_id: Hash256,
        input_data: Vec<u8>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolInvokeData {
            tool_id,
            input_data,
            max_metered_units: None,
            gas_limit: crate::primitives::tool::DEFAULT_CONTRACT_TOOL_GAS_LIMIT,
            milestones: vec![],
        };
        let tx = Transaction {
            tx_type: TxType::ToolInvoke,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a tool invocation transaction.
    pub fn build_invoke_tool(
        &mut self,
        tool_id: Hash256,
        input_data: Vec<u8>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolInvokeData {
            tool_id,
            input_data,
            max_metered_units: None,
            gas_limit: crate::primitives::tool::DEFAULT_CONTRACT_TOOL_GAS_LIMIT,
            milestones: vec![],
        };
        let tx = Transaction {
            tx_type: TxType::ToolInvoke,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a metered tool invocation that authorizes up to
    /// `max_metered_units` billable units.
    pub fn build_invoke_metered_tool(
        &mut self,
        tool_id: Hash256,
        input_data: Vec<u8>,
        max_metered_units: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolInvokeData {
            tool_id,
            input_data,
            max_metered_units: Some(max_metered_units),
            gas_limit: crate::primitives::tool::DEFAULT_CONTRACT_TOOL_GAS_LIMIT,
            milestones: vec![],
        };
        let tx = Transaction {
            tx_type: TxType::ToolInvoke,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a milestone-escrowed tool invocation.
    pub fn build_invoke_milestone_tool(
        &mut self,
        tool_id: Hash256,
        input_data: Vec<u8>,
        milestones: Vec<crate::primitives::tool::ToolMilestoneDef>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolInvokeData {
            tool_id,
            input_data,
            max_metered_units: None,
            gas_limit: crate::primitives::tool::DEFAULT_CONTRACT_TOOL_GAS_LIMIT,
            milestones,
        };
        let tx = Transaction {
            tx_type: TxType::ToolInvoke,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a provider result submission for an escrowed HTTP tool job.
    pub fn build_submit_tool_result(
        &mut self,
        job_id: Hash256,
        result_hash: Hash256,
        result_metadata: Vec<u8>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultSubmitData {
            job_id,
            result_hash,
            result_metadata,
            milestone_index: None,
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultSubmit,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a provider milestone result submission.
    pub fn build_submit_tool_milestone_result(
        &mut self,
        job_id: Hash256,
        milestone_index: u32,
        result_hash: Hash256,
        result_metadata: Vec<u8>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultSubmitData {
            job_id,
            result_hash,
            result_metadata,
            milestone_index: Some(milestone_index),
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultSubmit,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester acceptance for an escrowed HTTP tool job.
    pub fn build_accept_tool_result(
        &mut self,
        job_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultAcceptData {
            job_id,
            milestone_index: None,
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultAccept,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester acceptance for one milestone of a milestone job.
    pub fn build_accept_tool_milestone_result(
        &mut self,
        job_id: Hash256,
        milestone_index: u32,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultAcceptData {
            job_id,
            milestone_index: Some(milestone_index),
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultAccept,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a requester dispute for an escrowed HTTP tool job.
    pub fn build_dispute_tool_result(
        &mut self,
        job_id: Hash256,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultDisputeData {
            job_id,
            reason: reason.to_string(),
            milestone_index: None,
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultDispute,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester dispute for one milestone of a milestone job.
    pub fn build_dispute_tool_milestone_result(
        &mut self,
        job_id: Hash256,
        milestone_index: u32,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultDisputeData {
            job_id,
            reason: reason.to_string(),
            milestone_index: Some(milestone_index),
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultDispute,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an arbitrator resolution for an escrowed HTTP tool job.
    pub fn build_resolve_tool_result(
        &mut self,
        job_id: Hash256,
        provider_wins: bool,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultResolveData {
            job_id,
            provider_wins,
            reason: reason.to_string(),
            milestone_index: None,
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultResolve,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign arbitrator resolution for one milestone of a milestone job.
    pub fn build_resolve_tool_milestone_result(
        &mut self,
        job_id: Hash256,
        milestone_index: u32,
        provider_wins: bool,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolResultResolveData {
            job_id,
            provider_wins,
            reason: reason.to_string(),
            milestone_index: Some(milestone_index),
        };
        let tx = Transaction {
            tx_type: TxType::ToolResultResolve,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a manual timeout settlement for an escrowed HTTP tool job.
    pub fn build_expire_tool_job(
        &mut self,
        job_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = ToolJobExpireData { job_id };
        let tx = Transaction {
            tx_type: TxType::ToolJobExpire,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a provider usage report for a metered HTTP tool session.
    pub fn build_report_tool_usage(
        &mut self,
        session_id: Hash256,
        units_used: u64,
        result_hash: Hash256,
        result_metadata: Vec<u8>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolUsageReportData {
            session_id,
            units_used,
            result_hash,
            result_metadata,
        };
        let tx = Transaction {
            tx_type: TxType::ToolUsageReport,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester acceptance for a metered HTTP tool session.
    pub fn build_accept_tool_usage(
        &mut self,
        session_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolUsageAcceptData { session_id };
        let tx = Transaction {
            tx_type: TxType::ToolUsageAccept,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign requester dispute for a metered HTTP tool session.
    pub fn build_dispute_tool_usage(
        &mut self,
        session_id: Hash256,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolUsageDisputeData {
            session_id,
            reason: reason.to_string(),
        };
        let tx = Transaction {
            tx_type: TxType::ToolUsageDispute,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign arbitrator resolution for a metered HTTP tool session.
    pub fn build_resolve_tool_usage(
        &mut self,
        session_id: Hash256,
        provider_wins: bool,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolUsageResolveData {
            session_id,
            provider_wins,
            reason: reason.to_string(),
        };
        let tx = Transaction {
            tx_type: TxType::ToolUsageResolve,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign manual timeout settlement for a metered HTTP tool session.
    pub fn build_expire_tool_usage(
        &mut self,
        session_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::tool::ToolUsageExpireData { session_id };
        let tx = Transaction {
            tx_type: TxType::ToolUsageExpire,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a tool update transaction.
    pub fn build_update_tool(
        &mut self,
        _tool_id: Hash256,
        update: crate::primitives::tool::ToolUpdateData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ToolUpdate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&update)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign a single-payment agreement execution transaction.
    pub fn build_execute_agreement(
        &mut self,
        agreement_id: Hash256,
        result_hash: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_execute_milestone(agreement_id, result_hash, 0, fee)
    }

    /// Build and sign a milestone execution transaction.
    pub fn build_execute_milestone(
        &mut self,
        agreement_id: Hash256,
        result_hash: Hash256,
        milestone_index: u32,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = AgreementExecuteData {
            agreement_id,
            result_hash,
            milestone_index,
        };
        let tx = Transaction {
            tx_type: TxType::AgreementExecute,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agreement dispute transaction.
    pub fn build_dispute_agreement(
        &mut self,
        agreement_id: Hash256,
        reason: &str,
        fee: u64,
    ) -> Result<SignedTransaction> {
        self.build_dispute_agreement_with_milestone(agreement_id, reason, None, fee)
    }

    /// Build and sign an agreement dispute transaction, optionally targeting a milestone.
    pub fn build_dispute_agreement_with_milestone(
        &mut self,
        agreement_id: Hash256,
        reason: &str,
        milestone_index: Option<u32>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = AgreementDisputeData {
            agreement_id,
            reason: reason.to_string(),
            milestone_index,
        };
        let tx = Transaction {
            tx_type: TxType::AgreementDispute,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agreement accept transaction.
    pub fn build_accept_agreement(
        &mut self,
        agreement_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = AgreementAcceptData { agreement_id };
        let tx = Transaction {
            tx_type: TxType::AgreementAccept,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agreement resolve transaction with explicit N-way
    /// payouts plus explicit per-party dispute reputation effects.
    pub fn build_resolve_agreement(
        &mut self,
        agreement_id: Hash256,
        payouts: Vec<AgreementPayoutShare>,
        reputation_effects: Vec<AgreementDisputeReputationEffect>,
        reason: &str,
        milestone_index: Option<u32>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        if payouts.is_empty() {
            return Err(ZinchaError::InvalidTransaction(
                "Resolution payouts cannot be empty".into(),
            ));
        }
        let data = AgreementResolveData {
            agreement_id,
            payouts,
            reputation_effects,
            reason: reason.to_string(),
            milestone_index,
        };
        let tx = Transaction {
            tx_type: TxType::AgreementResolve,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an agreement cancel transaction (proposer only, before acceptance).
    pub fn build_cancel_agreement(
        &mut self,
        agreement_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = AgreementCancelData { agreement_id };
        let tx = Transaction {
            tx_type: TxType::AgreementCancel,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build and sign an arbitrator registration transaction.
    pub fn build_register_arbitrator(
        &mut self,
        name: &str,
        description: &str,
        stake: u64,
        fee_bps: u16,
        specializations: Vec<String>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::agreement::ArbitratorRegisterData {
            name: name.to_string(),
            description: description.to_string(),
            stake,
            fee_bps,
            specializations,
        };
        let tx = Transaction {
            tx_type: TxType::ArbitratorRegister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: stake,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    // -----------------------------------------------------------------------
    // Smart Contract operations
    // -----------------------------------------------------------------------

    /// Build a contract deployment transaction.
    pub fn build_deploy_contract(
        &mut self,
        bytecode: Vec<u8>,
        initial_balance: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::contract::ContractDeployData { bytecode };
        let tx = Transaction {
            tx_type: TxType::ContractDeploy,
            sender: self.address(),
            recipient: Address::zero(),
            amount: initial_balance,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build a contract call transaction.
    pub fn build_call_contract(
        &mut self,
        contract_address: Address,
        function: &str,
        args: Vec<u8>,
        call_value: u64,
        gas_limit: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::contract::ContractCallData {
            contract_address: contract_address.clone(),
            function: function.to_string(),
            args,
            gas_limit,
        };
        let tx = Transaction {
            tx_type: TxType::ContractCall,
            sender: self.address(),
            recipient: contract_address,
            amount: call_value,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build a contract call transaction through a stable route alias.
    pub fn build_call_contract_route(
        &mut self,
        deployer: Address,
        route_name: &str,
        function: &str,
        args: Vec<u8>,
        call_value: u64,
        gas_limit: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::contract::ContractRouteCallData {
            deployer,
            route_name: route_name.to_string(),
            function: function.to_string(),
            args,
            gas_limit,
        };
        let tx = Transaction {
            tx_type: TxType::ContractRouteCall,
            sender: self.address(),
            recipient: Address::zero(),
            amount: call_value,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build a contract source verification transaction.
    pub fn build_verify_contract_source(
        &mut self,
        contract_address: Address,
        proof: crate::primitives::contract::ContractSourceProof,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::contract::ContractVerifyData {
            contract_address: contract_address.clone(),
            proof,
        };
        let tx = Transaction {
            tx_type: TxType::ContractVerify,
            sender: self.address(),
            recipient: contract_address,
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build an authenticated contract ABI publication transaction.
    pub fn build_publish_contract_abi(
        &mut self,
        contract_address: Address,
        abi: crate::primitives::contract::ContractAbi,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::contract::ContractPublishAbiData {
            contract_address: contract_address.clone(),
            abi,
        };
        let tx = Transaction {
            tx_type: TxType::ContractPublishAbi,
            sender: self.address(),
            recipient: contract_address,
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    /// Build an immutable contract route retarget transaction.
    pub fn build_update_contract_route(
        &mut self,
        route_name: &str,
        target_contract_address: Address,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::contract::ContractRouteUpdateData {
            route_name: route_name.to_string(),
            target_contract_address: target_contract_address.clone(),
        };
        let tx = Transaction {
            tx_type: TxType::ContractRouteUpdate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
            max_priority_fee_per_gas: 0,
        };
        self.sign_transaction(tx)
    }

    // -----------------------------------------------------------------------
    // ZIP-20 Token operations
    // -----------------------------------------------------------------------

    pub fn build_create_token(
        &mut self,
        name: &str,
        symbol: &str,
        decimals: u8,
        initial_supply: u64,
        max_supply: Option<u64>,
        mint_authority: Option<Address>,
        burnable: bool,
        metadata: Vec<u8>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let max_supply = match (mint_authority.as_ref(), max_supply) {
            (None, None) => initial_supply,
            (_, Some(explicit_max_supply)) => explicit_max_supply,
            (_, None) => 0,
        };
        let data = crate::primitives::token::TokenCreateData {
            name: name.to_string(),
            symbol: symbol.to_string(),
            decimals,
            initial_supply,
            max_supply,
            burnable,
            mint_authority,
            metadata,
        };
        let tx = Transaction {
            tx_type: TxType::TokenCreate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    pub fn build_transfer_token(
        &mut self,
        token_id: Hash256,
        to: Address,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::token::TokenTransferData {
            token_id,
            to: to.clone(),
            amount,
        };
        let tx = Transaction {
            tx_type: TxType::TokenTransfer,
            sender: self.address(),
            recipient: to,
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    pub fn build_approve_token(
        &mut self,
        token_id: Hash256,
        spender: Address,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::token::TokenApproveData {
            token_id,
            spender: spender.clone(),
            amount,
        };
        let tx = Transaction {
            tx_type: TxType::TokenApprove,
            sender: self.address(),
            recipient: spender,
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    pub fn build_mint_token(
        &mut self,
        token_id: Hash256,
        to: Address,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::token::TokenMintData {
            token_id,
            to: to.clone(),
            amount,
        };
        let tx = Transaction {
            tx_type: TxType::TokenMint,
            sender: self.address(),
            recipient: to,
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    pub fn build_update_token_mint_authority(
        &mut self,
        token_id: Hash256,
        mint_authority: Option<Address>,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::token::TokenUpdateAuthorityData {
            token_id,
            mint_authority,
        };
        let tx = Transaction {
            tx_type: TxType::TokenUpdateAuthority,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    pub fn build_burn_token(
        &mut self,
        token_id: Hash256,
        amount: u64,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let data = crate::primitives::token::TokenBurnData { token_id, amount };
        let tx = Transaction {
            tx_type: TxType::TokenBurn,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&data)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    // -----------------------------------------------------------------------
    // Deregister / Destroy transactions (state cleanup with deposit refund)
    // -----------------------------------------------------------------------

    /// Deregister the agent at this wallet's address. Reclaims storage deposit.
    /// Fails if the agent has active tasks or agreements.
    pub fn build_deregister_agent(&mut self, fee: u64) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::AgentDeregister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Deregister a tool owned by this wallet. Reclaims storage deposit.
    pub fn build_deregister_tool(
        &mut self,
        tool_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ToolDeregister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: tool_id.as_bytes().to_vec(),
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Deregister as an arbitrator. Reclaims stake + storage deposit.
    /// Fails if there are active disputes assigned to this arbitrator.
    pub fn build_deregister_arbitrator(&mut self, fee: u64) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ArbitratorDeregister,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: vec![],
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Deactivate a contract deployed by this wallet. Reclaims storage deposit.
    pub fn build_deactivate_contract(
        &mut self,
        contract_address: Address,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::ContractDeactivate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: contract_address.0.to_vec(),
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Destroy a token created by this wallet. Only works if total_supply == 0.
    /// Reclaims storage deposit.
    pub fn build_destroy_token(
        &mut self,
        token_id: Hash256,
        fee: u64,
    ) -> Result<SignedTransaction> {
        let tx = Transaction {
            tx_type: TxType::TokenDestroy,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: token_id.as_bytes().to_vec(),
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Propose a new capability catalog entry. Proposed entries are usable
    /// immediately with pending status once included on chain.
    pub fn build_propose_capability(
        &mut self,
        mut proposal: CapabilityProposeData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        Self::normalize_capability_proposal(&mut proposal)?;
        let tx = Transaction {
            tx_type: TxType::CapabilityPropose,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&proposal)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Approve a pending capability catalog entry as an active curated entry.
    pub fn build_approve_capability(
        &mut self,
        mut approval: CapabilityApproveData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        Self::normalize_capability_approval(&mut approval)?;
        let tx = Transaction {
            tx_type: TxType::CapabilityApprove,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&approval)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Reject a pending capability catalog entry.
    pub fn build_reject_capability(
        &mut self,
        mut rejection: CapabilityRejectData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        rejection.slug = Self::normalize_capability_slug_field("slug", &rejection.slug)?;
        let tx = Transaction {
            tx_type: TxType::CapabilityReject,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&rejection)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    /// Deprecate an active capability catalog entry in favor of another slug.
    pub fn build_deprecate_capability(
        &mut self,
        mut deprecation: CapabilityDeprecateData,
        fee: u64,
    ) -> Result<SignedTransaction> {
        deprecation.slug = Self::normalize_capability_slug_field("slug", &deprecation.slug)?;
        deprecation.replacement =
            Self::normalize_capability_slug_field("replacement", &deprecation.replacement)?;
        let tx = Transaction {
            tx_type: TxType::CapabilityDeprecate,
            sender: self.address(),
            recipient: Address::zero(),
            amount: 0,
            fee,
            max_priority_fee_per_gas: 0,
            nonce: self.next_nonce(),
            timestamp: self.transaction_timestamp_ms(),
            reference_block_height: 0,
            reference_block_hash: Default::default(),
            max_valid_block_height: 0,
            data: bincode::serialize(&deprecation)?,
            chain_id: self.chain_id.clone(),
        };
        self.sign_transaction(tx)
    }

    fn normalize_capability_proposal(proposal: &mut CapabilityProposeData) -> Result<()> {
        proposal.slug = Self::normalize_capability_slug_field("slug", &proposal.slug)?;
        if let Some(parent) = proposal.parent.as_mut() {
            *parent = Self::normalize_capability_slug_field("parent", parent)?;
        }
        proposal.aliases = Self::normalize_capability_slug_list("alias", &proposal.aliases)?;
        proposal.related = Self::normalize_capability_slug_list("related", &proposal.related)?;
        Ok(())
    }

    fn normalize_capability_approval(approval: &mut CapabilityApproveData) -> Result<()> {
        approval.slug = Self::normalize_capability_slug_field("slug", &approval.slug)?;
        if let Some(Some(parent)) = approval.parent.as_mut() {
            *parent = Self::normalize_capability_slug_field("parent", parent)?;
        }
        if let Some(aliases) = approval.aliases.as_mut() {
            *aliases = Self::normalize_capability_slug_list("alias", aliases)?;
        }
        if let Some(related) = approval.related.as_mut() {
            *related = Self::normalize_capability_slug_list("related", related)?;
        }
        Ok(())
    }

    fn normalize_capability_slug_list(label: &str, values: &[String]) -> Result<Vec<String>> {
        values
            .iter()
            .map(|value| Self::normalize_capability_slug_field(label, value))
            .collect()
    }

    fn normalize_capability_slug_field(label: &str, value: &str) -> Result<String> {
        let normalized = value.trim().to_ascii_lowercase();
        normalize_capability_slug(&normalized)
            .map(|_| normalized)
            .map_err(|error| ZinchaError::InvalidCapability(format!("{label}: {error}")))
    }

    // -----------------------------------------------------------------------
    // Serialization helpers for RPC submission
    // -----------------------------------------------------------------------

    /// Serialize a signed transaction to hex bytes for API submission.
    pub fn tx_to_hex(signed_tx: &SignedTransaction) -> Result<String> {
        let bytes = bincode::serialize(signed_tx)?;
        Ok(hex::encode(bytes))
    }

    /// Deserialize a signed transaction from hex bytes.
    pub fn tx_from_hex(hex_str: &str) -> Result<SignedTransaction> {
        let bytes = hex::decode(hex_str).map_err(|e| ZinchaError::Serialization(e.to_string()))?;
        Ok(bincode::deserialize(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_bytes;

    struct TestExternalSigner {
        keypair: Keypair,
        invocation_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl TransactionSigner for TestExternalSigner {
        fn public_key(&self) -> PublicKey {
            self.keypair.public_key()
        }

        fn sign_transaction(&self, _tx: &Transaction, tx_hash: &Hash256) -> Result<Signature> {
            self.invocation_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.keypair.sign(tx_hash.as_bytes()))
        }
    }

    fn test_wallet() -> AgentWallet {
        AgentWallet::generate("zincha-test-1", "http://localhost:9944")
    }

    #[test]
    fn test_wallet_supports_custom_signer_backends() {
        let invocation_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let signer_key = Keypair::from_secret_bytes(&[17u8; 32]);
        let expected_address = signer_key.address();
        let mut wallet = AgentWallet::from_signer(
            TestExternalSigner {
                keypair: signer_key,
                invocation_count: invocation_count.clone(),
            },
            "zincha-test-1",
            "external://signer",
        );
        wallet.set_nonce(4);
        let recipient = Keypair::generate().address();
        let tx = wallet
            .build_transfer(recipient.clone(), 42, 7)
            .expect("build transfer with custom signer");

        assert_eq!(
            invocation_count.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(tx.verify().is_ok());
        assert_eq!(tx.sender(), &expected_address);
        assert_eq!(wallet.address(), expected_address);
        assert_eq!(
            wallet.public_key_hex(),
            hex::encode(tx.public_key.as_bytes())
        );
        assert_eq!(tx.transaction.recipient, recipient);
        assert_eq!(tx.transaction.nonce, 4);
    }

    #[test]
    fn test_build_transfer() {
        let mut wallet = test_wallet();
        let recipient = Keypair::generate().address();
        let tx = wallet
            .build_transfer(recipient.clone(), 1_000_000, 10)
            .unwrap();

        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::Transfer);
        assert_eq!(tx.transaction.sender, wallet.address());
        assert_eq!(tx.transaction.recipient, recipient);
        assert_eq!(tx.transaction.amount, 1_000_000);
        assert_eq!(tx.transaction.nonce, 0);
    }

    #[test]
    fn test_nonce_auto_increment() {
        let mut wallet = test_wallet();
        let recipient = Keypair::generate().address();

        let tx1 = wallet.build_transfer(recipient.clone(), 100, 10).unwrap();
        let tx2 = wallet.build_transfer(recipient.clone(), 200, 10).unwrap();
        let tx3 = wallet.build_transfer(recipient, 300, 10).unwrap();

        assert_eq!(tx1.transaction.nonce, 0);
        assert_eq!(tx2.transaction.nonce, 1);
        assert_eq!(tx3.transaction.nonce, 2);
    }

    #[test]
    fn test_build_register_agent() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_register_agent(
                "TestAgent-7B",
                "A general-purpose AI agent specializing in text generation and reasoning",
                vec![Capability::text_generation(), Capability::reasoning()],
                hash_bytes(b"model_weights_hash"),
                100,
            )
            .unwrap();

        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::AgentRegister);
        let data: AgentRegisterData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.neural_embedding, None);
    }

    #[test]
    fn test_build_capability_catalog_transactions() {
        let mut wallet = test_wallet();
        let propose = CapabilityProposeData {
            slug: " AI.Specialist.Test ".to_string(),
            display_name: "Specialist Test".to_string(),
            description: "A proposed test capability".to_string(),
            category: "ai".to_string(),
            parent: Some(" AI.Reasoning ".to_string()),
            aliases: vec!["AI.Test-Specialist".to_string()],
            keywords: vec!["test".to_string()],
            examples: vec!["Use for tests".to_string()],
            related: vec!["AI.Reasoning".to_string()],
        };
        let propose_tx = wallet
            .build_propose_capability(propose.clone(), 100)
            .expect("build capability propose");
        assert!(propose_tx.verify().is_ok());
        assert_eq!(propose_tx.transaction.tx_type, TxType::CapabilityPropose);
        let decoded: CapabilityProposeData =
            bincode::deserialize(&propose_tx.transaction.data).unwrap();
        assert_eq!(decoded.slug, "ai.specialist.test");
        assert_eq!(decoded.parent.as_deref(), Some("ai.reasoning"));
        assert_eq!(decoded.aliases, ["ai.test-specialist"]);
        assert_eq!(decoded.related, ["ai.reasoning"]);

        let approve = CapabilityApproveData {
            slug: " AI.Specialist.Test ".to_string(),
            display_name: Some("Specialist Test".to_string()),
            description: None,
            category: Some("ai".to_string()),
            parent: Some(Some(" AI.Reasoning ".to_string())),
            aliases: Some(vec!["AI.Test-Specialist".to_string()]),
            keywords: Some(vec!["test".to_string()]),
            examples: None,
            related: Some(vec!["AI.Reasoning".to_string()]),
        };
        let approve_tx = wallet
            .build_approve_capability(approve, 0)
            .expect("build capability approve");
        assert_eq!(approve_tx.transaction.tx_type, TxType::CapabilityApprove);
        let decoded: CapabilityApproveData =
            bincode::deserialize(&approve_tx.transaction.data).unwrap();
        assert_eq!(decoded.slug, "ai.specialist.test");
        assert_eq!(decoded.parent, Some(Some("ai.reasoning".to_string())));
        assert_eq!(
            decoded.aliases,
            Some(vec!["ai.test-specialist".to_string()])
        );
        assert_eq!(decoded.related, Some(vec!["ai.reasoning".to_string()]));

        let reject_tx = wallet
            .build_reject_capability(
                CapabilityRejectData {
                    slug: " AI.Specialist.Test ".to_string(),
                    reason: "duplicate".to_string(),
                },
                0,
            )
            .expect("build capability reject");
        assert_eq!(reject_tx.transaction.tx_type, TxType::CapabilityReject);
        let decoded: CapabilityRejectData =
            bincode::deserialize(&reject_tx.transaction.data).unwrap();
        assert_eq!(decoded.slug, "ai.specialist.test");

        let deprecate_tx = wallet
            .build_deprecate_capability(
                CapabilityDeprecateData {
                    slug: " AI.Specialist.Test ".to_string(),
                    replacement: " AI.Reasoning ".to_string(),
                    reason: "merged".to_string(),
                },
                0,
            )
            .expect("build capability deprecate");
        assert_eq!(
            deprecate_tx.transaction.tx_type,
            TxType::CapabilityDeprecate
        );
        let decoded: CapabilityDeprecateData =
            bincode::deserialize(&deprecate_tx.transaction.data).unwrap();
        assert_eq!(decoded.slug, "ai.specialist.test");
        assert_eq!(decoded.replacement, "ai.reasoning");

        let invalid = wallet
            .build_propose_capability(
                CapabilityProposeData {
                    slug: "not valid".to_string(),
                    display_name: "Invalid".to_string(),
                    description: "Invalid".to_string(),
                    category: "ai".to_string(),
                    parent: None,
                    aliases: Vec::new(),
                    keywords: Vec::new(),
                    examples: Vec::new(),
                    related: Vec::new(),
                },
                0,
            )
            .expect_err("invalid capability slug must fail before signing");
        assert!(matches!(invalid, ZinchaError::InvalidCapability(_)));
    }

    #[test]
    fn test_build_update_agent_semantic_change_clears_client_neural_embedding_by_default() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_update_agent(
                Some("Updated Agent".to_string()),
                None,
                None,
                None,
                None,
                None,
                100,
            )
            .unwrap();

        let data: AgentUpdateData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.neural_embedding, Some(Vec::new()));
    }

    #[test]
    fn test_build_update_agent_nonsemantic_change_preserves_client_neural_embedding() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_update_agent(None, None, None, None, None, Some(false), 100)
            .unwrap();

        let data: AgentUpdateData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.neural_embedding, None);
    }

    #[test]
    fn test_build_update_agent_full_accepts_explicit_client_neural_embedding() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_update_agent_full(
                Some("Updated Agent".to_string()),
                Some("Updated through explicit embedding maintenance".to_string()),
                Some(vec![0.25, 0.5, 0.75]),
                None,
                Some(vec![Capability::reasoning()]),
                None,
                None,
                None,
                None,
                100,
            )
            .unwrap();

        let data: AgentUpdateData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.neural_embedding, Some(vec![0.25, 0.5, 0.75]));
    }

    #[test]
    fn test_build_submit_task() {
        let mut wallet = test_wallet();
        let deadline = AgentWallet::now_ms() + 3_600_000; // 1 hour
        let tx = wallet
            .build_submit_task(
                "Analyze market data and generate report",
                vec![Capability::data_analysis(), Capability::reasoning()],
                50_000_000,
                5,
                deadline,
                vec![],
                100,
            )
            .unwrap();

        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::TaskSubmit);
        let data: TaskSubmitData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.neural_embedding, None);
    }

    #[test]
    fn test_build_register_tool_omits_neural_without_embed_service() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_register_tool(
                "VectorSearch",
                "Semantic search over documents",
                "https://tools.example/search",
                1_000_000,
                vec![Capability::new("ai.search")],
                "1.0.0",
                100,
            )
            .unwrap();

        let data: crate::primitives::tool::ToolRegisterData =
            bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.neural_embedding, None);
    }

    #[test]
    fn test_build_update_contract_route() {
        let mut wallet = test_wallet();
        let target = Keypair::generate().address();
        let tx = wallet
            .build_update_contract_route("stable", target.clone(), 100)
            .unwrap();

        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::ContractRouteUpdate);
        assert_eq!(tx.transaction.recipient, Address::zero());
        let data: crate::primitives::contract::ContractRouteUpdateData =
            bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.route_name, "stable");
        assert_eq!(data.target_contract_address, target);
    }

    #[test]
    fn test_build_call_contract_route() {
        let mut wallet = test_wallet();
        let deployer = Keypair::generate().address();
        let tx = wallet
            .build_call_contract_route(
                deployer.clone(),
                "stable",
                "run",
                b"payload".to_vec(),
                123,
                456_789,
                100,
            )
            .unwrap();

        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::ContractRouteCall);
        assert_eq!(tx.transaction.recipient, Address::zero());
        assert_eq!(tx.transaction.amount, 123);
        let data: crate::primitives::contract::ContractRouteCallData =
            bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.deployer, deployer);
        assert_eq!(data.route_name, "stable");
        assert_eq!(data.function, "run");
        assert_eq!(data.args, b"payload".to_vec());
        assert_eq!(data.gas_limit, 456_789);
    }

    #[test]
    fn test_tx_hex_roundtrip() {
        let mut wallet = test_wallet();
        let recipient = Keypair::generate().address();
        let tx = wallet.build_transfer(recipient, 1_000_000, 10).unwrap();

        let hex_str = AgentWallet::tx_to_hex(&tx).unwrap();
        let recovered = AgentWallet::tx_from_hex(&hex_str).unwrap();

        assert_eq!(tx.tx_hash(), recovered.tx_hash());
        assert!(recovered.verify().is_ok());
    }

    #[test]
    fn test_build_register_validator() {
        let mut wallet = test_wallet();
        let tx = wallet.build_register_validator(1_000_000_000, 100).unwrap();
        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::ValidatorRegister);
        assert_eq!(tx.transaction.amount, 1_000_000_000);
        let decoded: ValidatorUpdateData = bincode::deserialize(&tx.transaction.data).unwrap();
        let decoded_key = decoded
            .vrf_public_key
            .expect("default helper should publish VRF key");
        assert_eq!(
            decoded_key.as_bytes(),
            wallet.signer_public_key().as_bytes()
        );
    }

    #[test]
    fn test_build_register_validator_with_vrf_public_key() {
        let mut wallet = test_wallet();
        let vrf_key = Keypair::generate();
        let err = wallet
            .build_register_validator_with_vrf_public_key(1_000_000_000, vrf_key.public_key(), 100)
            .expect_err("mismatched VRF key must be rejected");
        assert!(
            err.to_string().contains("wallet signing public key"),
            "expected signer-binding error, got {err}",
        );
    }

    #[test]
    fn test_build_register_validator_with_update_defaults_vrf_public_key_to_wallet_key() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_register_validator_with_update(
                1_000_000_000,
                ValidatorUpdateData {
                    executor_services: vec![ValidatorExecutorService {
                        partition_id: 0,
                        rpc_endpoint: "127.0.0.1:41000".to_string(),
                        executor_public_key: Keypair::generate().public_key(),
                    }],
                    vrf_public_key: None,
                },
                100,
            )
            .unwrap();
        let decoded: ValidatorUpdateData = bincode::deserialize(&tx.transaction.data).unwrap();
        let decoded_key = decoded
            .vrf_public_key
            .expect("wallet should backfill VRF key");
        assert_eq!(
            decoded_key.as_bytes(),
            wallet.signer_public_key().as_bytes()
        );
        assert_eq!(decoded.executor_services.len(), 1);
    }

    #[test]
    fn test_build_update_validator() {
        let mut wallet = test_wallet();
        let update = ValidatorUpdateData {
            executor_services: vec![ValidatorExecutorService {
                partition_id: 0,
                rpc_endpoint: "127.0.0.1:41000".to_string(),
                executor_public_key: Keypair::generate().public_key(),
            }],
            vrf_public_key: None,
        };
        let tx = wallet.build_update_validator(update.clone(), 100).unwrap();
        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::ValidatorUpdate);
        assert_eq!(tx.transaction.amount, 0);
        let decoded: ValidatorUpdateData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(decoded.executor_services.len(), 1);
        assert_eq!(decoded.executor_services[0].partition_id, 0);
    }

    #[test]
    fn test_build_update_validator_vrf_public_key() {
        let mut wallet = test_wallet();
        let vrf_key = Keypair::generate();
        let err = wallet
            .build_update_validator_vrf_public_key(vrf_key.public_key(), 100)
            .expect_err("mismatched VRF key must be rejected");
        assert!(
            err.to_string().contains("wallet signing public key"),
            "expected signer-binding error, got {err}",
        );
    }

    #[test]
    fn test_build_validator_vrf_contribution() {
        let mut wallet = test_wallet();
        let vrf_key = Keypair::generate();
        let prior_seed = hash_bytes(b"wallet-prior-seed");
        let err = wallet
            .build_validator_vrf_contribution(7, &prior_seed, &vrf_key, 100)
            .expect_err("mismatched VRF proof key must be rejected");
        assert!(
            err.to_string().contains("wallet signing public key"),
            "expected signer-binding error, got {err}",
        );
    }

    #[test]
    fn test_build_validator_vrf_commit() {
        let mut wallet = test_wallet();
        let vrf_key = Keypair::generate();
        let prior_seed = hash_bytes(b"wallet-prior-seed");
        let err = wallet
            .build_validator_vrf_commit(7, &prior_seed, &vrf_key, 100)
            .expect_err("mismatched VRF proof key must be rejected");
        assert!(
            err.to_string().contains("wallet signing public key"),
            "expected signer-binding error, got {err}",
        );
    }

    #[test]
    fn test_build_validator_vrf_commit_with_signer_key() {
        let signer = Keypair::from_secret_bytes(&[23u8; 32]);
        let mut wallet = AgentWallet::new(
            Keypair::from_secret_bytes(&signer.secret_bytes()),
            "zincha-test-1",
            "http://localhost:9944",
        );
        let prior_seed = hash_bytes(b"wallet-prior-seed");
        let commit_tx = wallet
            .build_validator_vrf_commit(7, &prior_seed, &signer, 100)
            .unwrap();
        assert!(commit_tx.verify().is_ok());
        assert_eq!(commit_tx.transaction.tx_type, TxType::ValidatorVrfCommit);
        let commit: ValidatorVrfCommitData =
            bincode::deserialize(&commit_tx.transaction.data).unwrap();
        assert_eq!(commit.target_epoch, 7);
        assert_ne!(commit.commitment, Hash256::zero());
    }

    #[test]
    fn test_build_validator_vrf_contribution_with_signer_key() {
        let signer = Keypair::from_secret_bytes(&[24u8; 32]);
        let mut wallet = AgentWallet::new(
            Keypair::from_secret_bytes(&signer.secret_bytes()),
            "zincha-test-1",
            "http://localhost:9944",
        );
        let prior_seed = hash_bytes(b"wallet-prior-seed");
        let tx = wallet
            .build_validator_vrf_contribution(7, &prior_seed, &signer, 100)
            .unwrap();
        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::ValidatorVrfContribution);
        assert_eq!(tx.transaction.amount, 0);
        let decoded: ValidatorVrfContributionData =
            bincode::deserialize(&tx.transaction.data).unwrap();
        decoded
            .verify_for_validator(
                &tx.transaction.chain_id,
                &wallet.address(),
                &wallet.signer_public_key(),
                &prior_seed,
            )
            .unwrap();
        assert_eq!(decoded.target_epoch, 7);
    }

    #[test]
    fn test_build_agreement() {
        let mut wallet = test_wallet();
        let service_provider = Keypair::generate().address();
        let tx = wallet
            .build_create_agreement(
                vec![wallet.address(), service_provider.clone()],
                b"terms: deliver report by Friday".to_vec(),
                500_000,
                AgentWallet::now_ms() + 86_400_000,
                None,
                vec![],
                service_provider.clone(),
                vec![AgreementPayoutShare {
                    recipient: service_provider.clone(),
                    share_bps: 10_000,
                }],
                None,
                100,
            )
            .unwrap();
        assert!(tx.verify().is_ok());
        assert_eq!(tx.transaction.tx_type, TxType::AgreementCreate);
        let data: AgreementCreateData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.service_provider, service_provider);
        assert_eq!(data.settlement_approver, None);
        assert_eq!(data.settlement_allocations.len(), 1);
        assert_eq!(data.milestones.len(), 1);
        assert_eq!(data.milestones[0].amount, 500_000);
    }

    #[test]
    fn test_build_agreement_with_settlement() {
        let mut wallet = test_wallet();
        let service_provider = Keypair::generate().address();
        let approver = Keypair::generate().address();
        let tx = wallet
            .build_create_agreement(
                vec![wallet.address(), service_provider.clone(), approver.clone()],
                b"terms: three-party review".to_vec(),
                900_000,
                AgentWallet::now_ms() + 86_400_000,
                None,
                vec![],
                service_provider.clone(),
                vec![
                    AgreementPayoutShare {
                        recipient: service_provider,
                        share_bps: 8_000,
                    },
                    AgreementPayoutShare {
                        recipient: wallet.address(),
                        share_bps: 2_000,
                    },
                ],
                Some(approver.clone()),
                100,
            )
            .unwrap();
        let data: AgreementCreateData = bincode::deserialize(&tx.transaction.data).unwrap();
        assert_eq!(data.parties.len(), 3);
        assert_eq!(data.settlement_approver, Some(approver));
        assert_eq!(data.settlement_allocations.len(), 2);
        assert_eq!(data.milestones.len(), 1);
        assert_eq!(data.milestones[0].amount, 900_000);
    }

    #[test]
    fn test_build_update_reputation_rejects_out_of_range_quality_score() {
        let mut wallet = test_wallet();
        let err = wallet
            .build_update_reputation(Hash256::from_bytes([0x91; 32]), 11.0, true, 100)
            .expect_err("out-of-range reputation score must be rejected");

        assert!(
            err.to_string()
                .contains("quality_score must be within [0.0, 10.0]"),
            "unexpected error: {err}",
        );
    }

    #[test]
    fn test_build_create_token_defaults_max_supply_when_mint_authority_is_absent() {
        let mut wallet = test_wallet();
        let tx = wallet
            .build_create_token(
                "Wallet Test Token",
                "WTT",
                6,
                42_000,
                None,
                None,
                true,
                Vec::new(),
                100,
            )
            .expect("build token create tx");
        let data: crate::primitives::token::TokenCreateData =
            bincode::deserialize(&tx.transaction.data).expect("decode token create payload");

        assert_eq!(data.initial_supply, 42_000);
        assert_eq!(data.max_supply, 42_000);
        assert!(data.mint_authority.is_none());
    }
}
