-- Migration: 010_create_rca_investigation_embeddings
-- Phase 12.2: pgvector storage foundation for incident retrieval
--
-- Enables the pgvector extension and creates the table that holds one
-- embedding per (investigation, document contract, embedding model):
--
--   public.rca_investigation_embeddings
--
-- Each row is the frozen embedding of the retrieval document rendered from one
-- RCA investigation.  The row is identified by a deterministic embedding_id:
--
--   embedding_id =
--   lowercase(hex(SHA-256(UTF-8(
--       investigation_id + "|" +
--       doc_version + "|" +
--       model_name + "|" +
--       model_revision
--   ))))
--
-- A new doc_version, model_name, or model_revision produces a distinct
-- embedding_id and therefore a new row, so embeddings produced under different
-- document contracts or models never overwrite one another and are never
-- compared with one another.
--
-- Initial contract values (supplied by the application layer, not defaulted
-- here):
--   doc_version    1.0.0
--   model_name     sentence-transformers/all-MiniLM-L6-v2   (384 dimensions)
--   model_revision an immutable pinned upstream Hugging Face commit/revision,
--                  fixed in a later phase.  No revision is defined here.
--
-- Requires the pgvector extension to be installed in the PostgreSQL image
-- (docker/postgres/Dockerfile).  CREATE EXTENSION must be run by a role
-- permitted to create extensions in the agentops database.
--
-- Apply AFTER 007_create_rca_tables.sql (FK requires the table):
--   psql -h localhost -U agentops -d agentops \
--     -f storage-consumer/migrations/010_create_rca_investigation_embeddings.sql
--
-- Retrieval metric contract:
--   - exact cosine distance operator: <=>
--   - similarity = 1.0 - (embedding <=> query_vector)
--   - Phase 12.2 performs exact (sequential) search only.  No approximate
--     nearest-neighbour index is created here.
--   - a future HNSW index would use vector_cosine_ops.
--
-- Column mapping:
--   embedding_id      TEXT          NOT NULL  PK
--   investigation_id  TEXT          NOT NULL  FK
--   doc_version       TEXT          NOT NULL
--   model_name        TEXT          NOT NULL
--   model_revision    TEXT          NOT NULL
--   document_text     TEXT          NOT NULL
--   embedding         vector(384)   NOT NULL
--   embedded_at       TIMESTAMPTZ   NOT NULL  DEFAULT NOW()

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS public.rca_investigation_embeddings (
    -- Deterministic identity: SHA-256 hex digest of
    -- (investigation_id + "|" + doc_version + "|" + model_name + "|" + model_revision).
    -- Exactly 64 lowercase hexadecimal characters; computed by the application layer.
    embedding_id TEXT NOT NULL,

    -- Investigation this embedding was rendered from.
    investigation_id TEXT NOT NULL,

    -- Version of the retrieval-document rendering contract, e.g. "1.0.0".
    doc_version TEXT NOT NULL,

    -- Embedding model identity.  model_revision pins the exact upstream weights.
    model_name TEXT NOT NULL,
    model_revision TEXT NOT NULL,

    -- The exact text that was embedded (kept for audit and re-ranking).
    document_text TEXT NOT NULL,

    -- 384 dimensions matches sentence-transformers/all-MiniLM-L6-v2.
    embedding vector(384) NOT NULL,

    -- Wall-clock time when this embedding was persisted.
    embedded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT rca_investigation_embeddings_pkey
        PRIMARY KEY (embedding_id),

    -- One embedding per investigation per (document contract, model, revision).
    CONSTRAINT rca_investigation_embeddings_inv_contract_model_uniq
        UNIQUE (investigation_id, doc_version, model_name, model_revision),

    -- RESTRICT: an investigation cannot be deleted while embeddings reference it.
    CONSTRAINT rca_investigation_embeddings_investigation_fk
        FOREIGN KEY (investigation_id)
        REFERENCES public.rca_investigations (investigation_id)
        ON DELETE RESTRICT,

    -- Format only: the database does not recompute the digest.
    CONSTRAINT rca_investigation_embeddings_embedding_id_format
        CHECK (embedding_id ~ '^[0-9a-f]{64}$')
);

-- Supports filtering a search to a single (document contract, model, revision)
-- so that only mutually comparable embeddings are ranked together.
CREATE INDEX IF NOT EXISTS rca_investigation_embeddings_contract_idx
    ON public.rca_investigation_embeddings
       (doc_version, model_name, model_revision);
