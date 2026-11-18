"""Prompt token counting for backends that have a local tokenizer.

The ExecuTorch backend ships a Hugging Face ``tokenizer.json``, so real counts
are available when the optional ``tokenizers`` package is installed.  Ollama
owns its tokenizer behind the HTTP API and does not expose a count, so it uses
the same conservative estimate (documented, and logged as an estimate).
"""

from __future__ import annotations

import logging
import math
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Average characters per token for English + numeric feature text with Llama 3.
_CHARS_PER_TOKEN = 4.0

_CACHE: dict[str, Any] = {}
_LOCK = threading.Lock()
_WARNED_NO_TOKENIZERS = False


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / _CHARS_PER_TOKEN))


def _load_tokenizer(tokenizer_path: Path) -> Any | None:
    """Return a cached ``tokenizers.Tokenizer`` or None if unavailable."""

    global _WARNED_NO_TOKENIZERS

    key = str(tokenizer_path)
    with _LOCK:
        if key in _CACHE:
            return _CACHE[key]
        try:
            from tokenizers import Tokenizer  # type: ignore[import-not-found]
        except Exception:
            if not _WARNED_NO_TOKENIZERS:
                logger.warning(
                    "The optional 'tokenizers' package is not installed; prompt "
                    "token counts are estimates. Install it on the Pi for exact "
                    "counts against the ExecuTorch tokenizer.json."
                )
                _WARNED_NO_TOKENIZERS = True
            _CACHE[key] = None
            return None
        try:
            tokenizer = Tokenizer.from_file(key)
        except Exception as exc:
            logger.warning(
                "Could not load tokenizer %s (%s); using token estimates",
                tokenizer_path,
                exc,
            )
            _CACHE[key] = None
            return None
        _CACHE[key] = tokenizer
        return tokenizer


def count_tokens(text: str, tokenizer_path: Path | None = None) -> tuple[int, str]:
    """Return ``(token_count, method)`` where method is "tokenizer" or "estimate"."""

    if tokenizer_path is not None and tokenizer_path.exists():
        tokenizer = _load_tokenizer(tokenizer_path)
        if tokenizer is not None:
            encoded = tokenizer.encode(text, add_special_tokens=False)
            return len(encoded.ids), "tokenizer"
    return estimate_tokens(text), "estimate"
