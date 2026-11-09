"""
incident-retrieval/sentence_transformer_backend.py

Phase 12.4: Local sentence-transformers embedding backend.

This module is the only place that touches the model library.  The library
is imported inside the load path, never at module import, so this module and
create_default_provider() work when sentence-transformers and torch are not
installed.

Locked model:
    MODEL_NAME                  sentence-transformers/all-MiniLM-L6-v2
    MODEL_REVISION              1110a243fdf4706b3f48f1d95db1a4f5529b4d41
                                (full Hugging Face repository commit hash)
    EMBEDDING_DIMENSION         384
    MODEL_MAX_SEQUENCE_LENGTH   256 word pieces, special tokens included

Loading:
    Lazy.  The model is loaded on the first call or by load(), once per
    backend instance, and reused.  After loading it is placed in evaluation
    mode explicitly.

Offline runtime:
    local_files_only=True by default.  The pinned snapshot must already be in
    the local Hugging Face cache; the backend never falls back to the
    network.  A missing library or a missing local snapshot raises
    RuntimeError.

    local_files_only alone is not enough to keep the Hugging Face libraries
    off the network: huggingface-hub still makes a metadata request to the
    Hub while loading unless it is in offline mode.  When local_files_only is
    True, load() therefore sets HF_HUB_OFFLINE=1 in the process environment
    before the model library is imported, and verifies that huggingface-hub
    is in offline mode.  If huggingface-hub was already imported in online
    mode, the setting can no longer take effect and load() raises
    RuntimeError instead of loading.  The environment is not touched when
    local_files_only=False is passed explicitly.

    One-time model acquisition (explicit, separate from runtime):

        python -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='sentence-transformers/all-MiniLM-L6-v2', revision='1110a243fdf4706b3f48f1d95db1a4f5529b4d41', allow_patterns=['modules.json','config.json','config_sentence_transformers.json','sentence_bert_config.json','1_Pooling/config.json','model.safetensors','tokenizer.json','tokenizer_config.json','special_tokens_map.json','vocab.txt'])"

Encoding:
    One text per call, never a batch: batching can change the float values
    slightly.  The text is passed to the model unchanged.

Truncation:
    The model's own sequence limit (256) is kept; it is never raised.  Text
    longer than the limit is truncated deterministically by the model's
    tokenizer: the first tokens are kept and the tail is dropped.  Oversized
    text is not rejected and not chunked.  token_usage() reports whether a
    given text will be truncated; __call__ returns only the vector.

No database access.  No network access unless local_files_only=False is
passed explicitly.

Public API:
    MODEL_NAME, MODEL_REVISION, EMBEDDING_DIMENSION, MODEL_MAX_SEQUENCE_LENGTH
    TokenUsage                  — token counts and truncation flag for a text
    SentenceTransformerBackend  — lazy local model backend
    create_default_provider()   — locked identity + lazy backend, nothing loaded
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional

from embedding_provider import EmbeddingModelIdentity, EmbeddingProvider


MODEL_NAME: str = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION: str = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
EMBEDDING_DIMENSION: int = 384
MODEL_MAX_SEQUENCE_LENGTH: int = 256

_DEVICE: str = "cpu"

# Environment variable read by huggingface-hub at import time.
_OFFLINE_ENV_VAR: str = "HF_HUB_OFFLINE"
_HUB_CONSTANTS_MODULE: str = "huggingface_hub.constants"


# ---------------------------------------------------------------------------
# Offline enforcement
# ---------------------------------------------------------------------------

def _require_hub_offline() -> None:
    """
    RuntimeError when huggingface-hub is imported but not in offline mode.

    Looks only at an already-imported module; it never imports the library.
    Does nothing when huggingface-hub has not been imported yet.
    """
    constants = sys.modules.get(_HUB_CONSTANTS_MODULE)
    if constants is None:
        return
    if getattr(constants, _OFFLINE_ENV_VAR, False) is not True:
        raise RuntimeError(
            "huggingface-hub is loaded in online mode, so local-only loading "
            "cannot be guaranteed to stay off the network. "
            f"Set {_OFFLINE_ENV_VAR}=1 before huggingface-hub is first "
            "imported in this process."
        )


def _enforce_offline_mode() -> None:
    """
    Put huggingface-hub into offline mode for this process.

    Sets HF_HUB_OFFLINE=1 so that a later import of the library starts
    offline, then rejects a library that was already imported online.
    """
    os.environ[_OFFLINE_ENV_VAR] = "1"
    _require_hub_offline()


# ---------------------------------------------------------------------------
# Token usage
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenUsage:
    """
    Token counts for one text under the loaded model's tokenizer.

    Attributes
    ----------
    tokens_without_special
        Word pieces produced from the text itself.
    tokens_with_special
        The same plus the model's special tokens; this is what is compared
        with the limit.
    token_limit
        The loaded model's maximum sequence length, special tokens included.
    truncated
        True when tokens_with_special exceeds token_limit, i.e. the tail of
        the text will not reach the model.
    """

    tokens_without_special: int
    tokens_with_special: int
    token_limit: int
    truncated: bool


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

def _default_model_factory(
    model_name: str,
    *,
    revision: str,
    local_files_only: bool,
    device: str,
) -> Any:
    """Load the model with sentence-transformers (imported here, lazily)."""
    from sentence_transformers import SentenceTransformer

    return SentenceTransformer(
        model_name,
        revision=revision,
        local_files_only=local_files_only,
        device=device,
    )


class SentenceTransformerBackend:
    """
    Lazy, local sentence-transformers backend: one text -> list of floats.

    Parameters
    ----------
    model_name, revision
        The model to load.  Default to the locked model and revision.
    local_files_only
        True (default) loads only from the local cache and never uses the
        network; load() also puts huggingface-hub into offline mode for the
        process.
    model_factory
        Test seam.  Called as
        model_factory(model_name, revision=..., local_files_only=..., device=...)
        and must return an object with encode(), eval(), tokenizer, and
        max_seq_length.  Defaults to loading with sentence-transformers.
    """

    def __init__(
        self,
        *,
        model_name: str = MODEL_NAME,
        revision: str = MODEL_REVISION,
        local_files_only: bool = True,
        model_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._model_name = model_name
        self._revision = revision
        self._local_files_only = local_files_only
        self._model_factory = model_factory
        self._model: Any = None

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def revision(self) -> str:
        return self._revision

    @property
    def local_files_only(self) -> bool:
        return self._local_files_only

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    def load(self) -> None:
        """
        Load the model if it is not loaded yet.

        Raises
        ------
        RuntimeError
            sentence-transformers is not installed; huggingface-hub is
            already imported in online mode while local-only loading was
            requested; the model could not be loaded from local files; or the
            loaded model's sequence limit is not MODEL_MAX_SEQUENCE_LENGTH.
            The network is never used as a fallback.
        """
        if self._model is not None:
            return

        if self._local_files_only:
            _enforce_offline_mode()

        factory = self._model_factory or _default_model_factory
        try:
            model = factory(
                self._model_name,
                revision=self._revision,
                local_files_only=self._local_files_only,
                device=_DEVICE,
            )
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is not installed; cannot load model "
                f"{self._model_name!r} at revision {self._revision!r}. "
                "Install incident-retrieval/requirements.txt."
            ) from exc
        except OSError as exc:
            if self._local_files_only:
                raise RuntimeError(
                    f"Model {self._model_name!r} at revision {self._revision!r} "
                    "is not available in the local Hugging Face cache. "
                    "Local-only loading was requested (local_files_only=True) "
                    "and the network was not used. Run the explicit one-time "
                    "model acquisition for this exact revision first."
                ) from exc
            raise RuntimeError(
                f"Model {self._model_name!r} at revision {self._revision!r} "
                "could not be loaded (local_files_only=False)."
            ) from exc

        if self._local_files_only:
            # The library is imported by now; confirm it really is offline.
            _require_hub_offline()

        model.eval()

        limit = model.max_seq_length
        if limit != MODEL_MAX_SEQUENCE_LENGTH:
            raise RuntimeError(
                f"Model {self._model_name!r} at revision {self._revision!r} "
                f"reports max_seq_length={limit!r}; expected "
                f"{MODEL_MAX_SEQUENCE_LENGTH}."
            )

        self._model = model

    def __call__(self, text: str) -> list[float]:
        """
        Embed one text and return the model's vector as plain Python floats.

        Raises
        ------
        ValueError
            text is not a single str, or the model did not return a
            one-dimensional vector.
        RuntimeError
            The model could not be loaded (see load()).
        """
        if not isinstance(text, str):
            raise ValueError(
                f"text must be a single str, got {type(text).__name__}"
            )
        self.load()

        output = self._model.encode(
            text,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        values = output.tolist() if hasattr(output, "tolist") else list(output)
        try:
            return [float(value) for value in values]
        except TypeError:
            raise ValueError(
                "model returned a non one-dimensional output for a single text"
            ) from None

    def token_usage(self, text: str) -> TokenUsage:
        """
        Report token counts for text and whether the model will truncate it.

        Uses the loaded model's tokenizer directly with truncation disabled,
        so the counts describe the whole text.

        Raises
        ------
        ValueError
            text is not a str.
        RuntimeError
            The model could not be loaded (see load()).
        """
        if not isinstance(text, str):
            raise ValueError(f"text must be str, got {type(text).__name__}")
        self.load()

        tokenizer = self._model.tokenizer
        without_special = len(
            tokenizer(
                text, add_special_tokens=False, truncation=False, verbose=False
            )["input_ids"]
        )
        with_special = len(
            tokenizer(
                text, add_special_tokens=True, truncation=False, verbose=False
            )["input_ids"]
        )
        limit = self._model.max_seq_length
        return TokenUsage(
            tokens_without_special=without_special,
            tokens_with_special=with_special,
            token_limit=limit,
            truncated=with_special > limit,
        )


# ---------------------------------------------------------------------------
# Default provider
# ---------------------------------------------------------------------------

def create_default_provider() -> EmbeddingProvider:
    """
    Build the provider for the locked model.

    Only constructs objects: the model is not loaded, no model library is
    imported, the environment is not changed, and no network access happens.
    The model loads from local files, in offline mode, on the first embed()
    call.
    """
    identity = EmbeddingModelIdentity(
        model_name=MODEL_NAME,
        model_revision=MODEL_REVISION,
        dimension=EMBEDDING_DIMENSION,
    )
    backend = SentenceTransformerBackend()
    return EmbeddingProvider(identity, backend)
