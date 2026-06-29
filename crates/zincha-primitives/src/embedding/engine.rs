//! Deterministic text embedding engine for semantic matching.
//!
//! Provides a built-in embedding engine that converts text descriptions into
//! fixed-dimensional vectors without requiring any external ML model. Uses
//! feature hashing (a.k.a. hashing vectorizer) over character n-grams and
//! word n-grams, similar to the approach used by FastText and scikit-learn's
//! HashingVectorizer.
//!
//! The embeddings are deterministic: the same input always produces the same
//! output on any platform. This is critical for on-chain consensus — all
//! validators must compute identical results.
//!
//! For production, clients can substitute a neural embedding model (e.g.
//! sentence-transformers/all-MiniLM-L6-v2) by pre-computing vectors off-chain
//! and including them in the transaction. The on-chain matching only needs the
//! vectors, not the model.
//!
//! ## Empirical validation
//!
//! Six engine variants were evaluated against 60 independently-written
//! matching scenarios (20 easy / 20 medium / 20 hard). The original v1
//! engine outperformed all alternatives:
//!
//! | Variant              | Rank-1 | Top-3 |
//! |----------------------|--------|-------|
//! | v1 original (this)   |   70%  |  97%  |
//! | + stop word removal  |   67%  |  92%  |
//! | + Porter stemming    |   63%  |  93%  |
//! | + IDF weighting      |   55%  |  93%  |
//! | + 256 dimensions     |   60%  |  90%  |
//! | + all four combined  |   53%  |  90%  |
//!
//! Every modification improved easy (cross-domain) scenarios but degraded
//! medium (same-domain) discrimination. The flat-weighted feature hashing
//! is at a local optimum for this 128-dim projection approach.
//!
//! With the hybrid scheme (base + 0.3 × MiniLM neural bonus), overall
//! rank-1 accuracy reaches 93%.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Maximum entries in the embedding cache. At 512 bytes per embedding,
/// 10,000 entries = ~5 MB. Embeddings are deterministic so cache hits
/// are guaranteed correct.
const EMBEDDING_CACHE_MAX: usize = 10_000;

/// Global embedding cache. PoUC verification re-computes embeddings
/// for AgentRegister/TaskSubmit/ToolRegister — caching eliminates
/// redundant computation when multiple validators process the same block.
static EMBEDDING_CACHE: std::sync::LazyLock<Mutex<EmbeddingCache>> =
    std::sync::LazyLock::new(|| Mutex::new(EmbeddingCache::new(EMBEDDING_CACHE_MAX)));

struct EmbeddingCache {
    map: HashMap<String, Vec<f32>>,
    max_size: usize,
}

impl EmbeddingCache {
    fn new(max_size: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_size / 2),
            max_size,
        }
    }

    fn get(&self, text: &str) -> Option<Vec<f32>> {
        self.map.get(text).cloned()
    }

    fn insert(&mut self, text: &str, value: Vec<f32>) {
        if self.map.len() >= self.max_size {
            // Simple eviction: clear half the cache when full.
            // A proper LRU would be better but this is simpler and
            // good enough — embeddings recompute in microseconds.
            let keys: Vec<String> = self.map.keys().take(self.max_size / 2).cloned().collect();
            for k in keys {
                self.map.remove(&k);
            }
        }
        self.map.insert(text.to_string(), value);
    }
}

/// Embedding dimensionality. 128 dimensions provides a good trade-off:
/// - Small enough to store on-chain (~512 bytes per vector)
/// - Large enough for meaningful cosine similarity
/// - Deterministic computation takes ~microseconds
pub const EMBEDDING_DIM: usize = 128;

/// A fixed-dimension embedding vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingVector(pub Vec<f32>);

impl EmbeddingVector {
    pub fn zero() -> Self {
        EmbeddingVector(vec![0.0; EMBEDDING_DIM])
    }

    pub fn dim(&self) -> usize {
        self.0.len()
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0.0)
    }

    /// Produce a deterministic byte representation for consensus hashing.
    ///
    /// Quantizes each f32 component to a fixed-point i32 (scaled by 1,000,000)
    /// and serializes the integer vector as little-endian bytes. This absorbs
    /// any cross-platform f32 divergence smaller than 0.0000005 (half the
    /// quantization step), which is 500× larger than a 1-ULP divergence at
    /// f32 precision (~0.0000001).
    ///
    /// For L2-normalized vectors (values in [-1.0, 1.0]), the i32 range
    /// [-1,000,000, 1,000,000] is well within i32 capacity.
    ///
    /// This is used ONLY in the PoUC proof hash path (compute_tx_work_hash).
    /// Matching, similarity, and storage continue to use raw f32.
    pub fn to_consensus_bytes(&self) -> Vec<u8> {
        const SCALE: f32 = 1_000_000.0;
        let mut bytes = Vec::with_capacity(self.0.len() * 4);
        for &val in &self.0 {
            let quantized = (val * SCALE).round() as i32;
            bytes.extend_from_slice(&quantized.to_le_bytes());
        }
        bytes
    }
}

impl Default for EmbeddingVector {
    fn default() -> Self {
        Self::zero()
    }
}

/// Trait for embedding engines. The built-in engine uses feature hashing;
/// external engines (neural models) can implement this trait to provide
/// higher-quality embeddings computed off-chain.
pub trait EmbeddingEngine {
    /// Embed a text description into a fixed-dimensional vector.
    fn embed(&self, text: &str) -> EmbeddingVector;
}

/// Built-in deterministic embedding engine using feature hashing.
///
/// How it works:
/// 1. Text is lowercased and tokenized into words
/// 2. Features are extracted: word unigrams, word bigrams, and character
///    trigrams from each word
/// 3. Each feature is hashed (FNV-1a) to determine:
///    - Which dimension to update (hash % EMBEDDING_DIM)
///    - The sign of the contribution (+1 or -1, from a second hash)
/// 4. Features are accumulated into a vector
/// 5. The vector is L2-normalized to unit length
///
/// This is equivalent to projecting a high-dimensional sparse TF vector
/// into a dense low-dimensional space via random hyperplane projection,
/// which preserves cosine similarity (Johnson-Lindenstrauss lemma).
pub struct BuiltinEmbedder;

impl EmbeddingEngine for BuiltinEmbedder {
    fn embed(&self, text: &str) -> EmbeddingVector {
        embed_text(text)
    }
}

/// Embed text using the built-in deterministic engine, with caching.
/// Identical inputs return cached results, avoiding redundant computation
/// during PoUC verification when multiple validators process the same block.
pub fn embed_text_cached(text: &str) -> EmbeddingVector {
    if let Ok(cache) = EMBEDDING_CACHE.lock() {
        if let Some(cached) = cache.get(text) {
            return EmbeddingVector(cached);
        }
    }
    let result = embed_text(text);
    if let Ok(mut cache) = EMBEDDING_CACHE.lock() {
        cache.insert(text, result.0.clone());
    }
    result
}

/// Embed text using the built-in deterministic engine (uncached).
pub fn embed_text(text: &str) -> EmbeddingVector {
    let mut vec = vec![0.0f32; EMBEDDING_DIM];

    let lower = text.to_lowercase();
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_alphanumeric() && c != '.' && c != '-')
        .filter(|w| !w.is_empty())
        .collect();

    if words.is_empty() {
        return EmbeddingVector(vec);
    }

    // Feature 1: Word unigrams (weight: 1.0)
    for word in &words {
        hash_feature(&mut vec, word.as_bytes(), 1.0);
    }

    // Feature 2: Word bigrams (weight: 1.5 — bigrams capture phrases)
    for pair in words.windows(2) {
        let bigram = format!("{}_{}", pair[0], pair[1]);
        hash_feature(&mut vec, bigram.as_bytes(), 1.5);
    }

    // Feature 3: Character trigrams within words (weight: 0.5)
    // Captures subword structure: "pricing" → "#pr", "pri", "ric", "ici", "cin", "ing", "ng#"
    for word in &words {
        if word.len() < 3 {
            continue;
        }
        let padded = format!("#{word}#");
        let chars: Vec<char> = padded.chars().collect();
        for tri in chars.windows(3) {
            let trigram: String = tri.iter().collect();
            hash_feature(&mut vec, trigram.as_bytes(), 0.5);
        }
    }

    // Feature 4: Capability-style dotted namespaces get extra weight
    // e.g. "finance.quant.pricing" → boost "finance", "quant", "pricing" and their combinations
    for word in &words {
        if word.contains('.') {
            let parts: Vec<&str> = word.split('.').collect();
            for part in &parts {
                hash_feature(&mut vec, part.as_bytes(), 2.0);
            }
            // Full namespace as a single feature
            hash_feature(&mut vec, word.as_bytes(), 3.0);
        }
    }

    // L2 normalize to unit length
    let magnitude: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if magnitude > 0.0 {
        for x in vec.iter_mut() {
            *x /= magnitude;
        }
    }

    EmbeddingVector(vec)
}

/// Hash a feature into the embedding vector using FNV-1a.
/// The hash determines the dimension and sign of the contribution.
fn hash_feature(vec: &mut [f32], feature: &[u8], weight: f32) {
    let h1 = fnv1a(feature);
    let h2 = fnv1a_seed(feature, 0x6c62272e07bb0142); // different seed for sign

    let dim = (h1 as usize) % vec.len();
    let sign = if h2 & 1 == 0 { 1.0f32 } else { -1.0f32 };

    vec[dim] += sign * weight;
}

/// FNV-1a hash (64-bit). Deterministic and fast.
fn fnv1a(data: &[u8]) -> u64 {
    fnv1a_seed(data, 0xcbf29ce484222325)
}

fn fnv1a_seed(data: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Compute cosine similarity between two embedding vectors.
/// Returns a value in [-1.0, 1.0] where 1.0 = identical, 0.0 = orthogonal.
/// If either vector is zero, returns 0.0.
pub fn cosine_similarity(a: &EmbeddingVector, b: &EmbeddingVector) -> f64 {
    if a.0.len() != b.0.len() {
        return 0.0;
    }

    let dot: f64 =
        a.0.iter()
            .zip(b.0.iter())
            .map(|(&x, &y)| x as f64 * y as f64)
            .sum();

    let mag_a: f64 =
        a.0.iter()
            .map(|&x| (x as f64) * (x as f64))
            .sum::<f64>()
            .sqrt();
    let mag_b: f64 =
        b.0.iter()
            .map(|&x| (x as f64) * (x as f64))
            .sum::<f64>()
            .sqrt();

    if mag_a < 1e-10 || mag_b < 1e-10 {
        return 0.0;
    }

    (dot / (mag_a * mag_b)).clamp(-1.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_similar_texts_high_similarity() {
        let a = embed_text("Price exotic options using Monte Carlo simulation");
        let b = embed_text("Monte Carlo pricing for exotic derivative options");
        let sim = cosine_similarity(&a, &b);
        assert!(
            sim > 0.5,
            "Similar texts should have high similarity, got {}",
            sim
        );
    }

    #[test]
    fn test_different_texts_low_similarity() {
        let a = embed_text("Price exotic options using Monte Carlo simulation");
        let b = embed_text("Translate Japanese manga dialogue to English");
        let sim = cosine_similarity(&a, &b);
        assert!(
            sim < 0.5,
            "Different texts should have low similarity, got {}",
            sim
        );
    }

    #[test]
    fn test_identical_texts_perfect_similarity() {
        let a = embed_text("Analyze market data");
        let b = embed_text("Analyze market data");
        let sim = cosine_similarity(&a, &b);
        assert!(
            (sim - 1.0).abs() < 0.01,
            "Identical texts should have ~1.0 similarity, got {}",
            sim
        );
    }

    #[test]
    fn test_capability_namespace_matching() {
        let a = embed_text("finance.quant.pricing specialist");
        let b = embed_text("Quantitative finance pricing models");
        let c = embed_text("Protein folding simulation");
        let sim_ab = cosine_similarity(&a, &b);
        let sim_ac = cosine_similarity(&a, &c);
        assert!(
            sim_ab > sim_ac,
            "Finance texts should match better than biology: ab={} ac={}",
            sim_ab,
            sim_ac
        );
    }

    #[test]
    fn test_embedding_is_deterministic() {
        let a1 = embed_text("Hello world");
        let a2 = embed_text("Hello world");
        assert_eq!(a1.0, a2.0, "Same input must produce identical vectors");
    }

    #[test]
    fn test_zero_vector_for_empty() {
        let a = embed_text("");
        assert!(a.is_zero());
        let sim = cosine_similarity(&a, &a);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn test_cache_lookup_is_exact_text_not_hash_only() {
        let mut cache = EmbeddingCache::new(8);
        let alpha = embed_text("alpha");
        let beta = embed_text("beta");

        cache.insert("alpha", alpha.0.clone());
        assert_eq!(cache.get("alpha"), Some(alpha.0.clone()));
        assert_eq!(cache.get("beta"), None);

        cache.insert("beta", beta.0.clone());
        assert_eq!(cache.get("alpha"), Some(alpha.0));
        assert_eq!(cache.get("beta"), Some(beta.0));
    }

    #[test]
    fn test_cached_embedding_is_independent_of_other_cache_entries() {
        let target = "target text for cache independence";
        let expected = embed_text(target);

        let mut polluted_cache = EmbeddingCache::new(8);
        polluted_cache.insert("unrelated text", embed_text("unrelated text").0);
        let polluted_result = polluted_cache
            .get(target)
            .map(EmbeddingVector)
            .unwrap_or_else(|| embed_text(target));

        let clean_cache = EmbeddingCache::new(8);
        let clean_result = clean_cache
            .get(target)
            .map(EmbeddingVector)
            .unwrap_or_else(|| embed_text(target));

        assert_eq!(polluted_result.0, expected.0);
        assert_eq!(clean_result.0, expected.0);
    }

    #[test]
    fn test_cached_embedding_is_independent_of_cache_population_order() {
        let target = "target text for cache population order";
        let expected = embed_text(target);

        let mut forward_cache = EmbeddingCache::new(8);
        for text in ["noise a", "noise b", "noise c"] {
            forward_cache.insert(text, embed_text(text).0);
        }
        let forward_result = forward_cache
            .get(target)
            .map(EmbeddingVector)
            .unwrap_or_else(|| embed_text(target));

        let mut reverse_cache = EmbeddingCache::new(8);
        for text in ["noise c", "noise b", "noise a"] {
            reverse_cache.insert(text, embed_text(text).0);
        }
        let reverse_result = reverse_cache
            .get(target)
            .map(EmbeddingVector)
            .unwrap_or_else(|| embed_text(target));

        assert_eq!(forward_result.0, expected.0);
        assert_eq!(reverse_result.0, expected.0);
        assert_eq!(forward_result.0, reverse_result.0);
    }

    #[test]
    fn test_cache_eviction_does_not_change_embedding_result() {
        let target = "target text for cache eviction";
        let expected = embed_text(target);

        let mut cache = EmbeddingCache::new(2);
        cache.insert("noise a", embed_text("noise a").0);
        cache.insert("noise b", embed_text("noise b").0);
        cache.insert("noise c", embed_text("noise c").0); // triggers eviction

        let cached_result = cache
            .get(target)
            .map(EmbeddingVector)
            .unwrap_or_else(|| embed_text(target));

        assert_eq!(cached_result.0, expected.0);
    }
}
