pub mod engine;

pub use engine::{
    cosine_similarity, embed_text, embed_text_cached, EmbeddingEngine, EmbeddingVector,
    EMBEDDING_DIM,
};
