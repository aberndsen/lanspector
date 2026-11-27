"""PII keyword and optional named-entity content scanning for crawled files."""

from __future__ import annotations

import importlib
import pathlib
import re

import openpyxl
from loguru import logger

from lanspector.constants import (
    MAX_PII_FILE_BYTES,
    MAX_PII_LINE_BYTES,
    PII_KEYWORDS,
    PII_PROPER_NAME_LABEL,
    PII_SNIPPET_LENGTH,
)
from lanspector.datatypes import PiiFinding
from lanspector.platform import open_read_noatime

_PII_WORD_REGEXES: tuple[tuple[int, re.Pattern[str]], ...] = tuple(
    (idx, re.compile(rf"(?P<word>{pattern})", re.I))
    for idx, pattern in enumerate(PII_KEYWORDS)
    if pattern != PII_PROPER_NAME_LABEL
)
_PII_NAME_REGEX: re.Pattern[str] = re.compile(
    r"(?:^|[^a-zA-Z0-9])("
    + "|".join(k for k in PII_KEYWORDS if k != PII_PROPER_NAME_LABEL)
    + r")(?:$|[^a-zA-Z0-9])",
    re.I,
)
_TEXT_EXTENSIONS: frozenset[str] = frozenset({".txt", ".csv", ".tsv", ".md", ".json", ".log"})
_EXCEL_EXTENSIONS: frozenset[str] = frozenset({".xlsx", ".xlsm"})


# ---------------------------------------------------------------------------
# Primary public routines
# ---------------------------------------------------------------------------


def scan_file_for_pii(
    path: str | pathlib.Path,
    max_rows: int = 10,
    use_ner: bool = False,
) -> list[PiiFinding]:
    """Inspect a supported file's contents and return detected PII findings.

    Parameters
    ----------
    path
        Path to the file to inspect.
    max_rows
        Maximum number of lines (for text files) or rows per sheet (for Excel files)
        to inspect.
    use_ner
        When ``True`` and ``nltk`` models are installed locally, also detect proper
        person names via named-entity recognition.

    Returns
    -------
    list[PiiFinding]
        Detected PII keyword and/or proper-name matches with contextual snippets.
    """
    text = extract_file_text(path, max_rows=max_rows)
    if not text:
        return []
    return search_text_for_pii(text, use_ner=use_ner)


def search_text_for_pii(contents: str, use_ner: bool = False) -> list[PiiFinding]:
    """Search extracted text *contents* for PII keywords and optional person names.

    Parameters
    ----------
    contents
        Text content extracted from a file.
    use_ner
        When ``True``, attempt optional NLTK named-entity person detection if
        ``nltk`` and its corpora are already installed locally.

    Returns
    -------
    list[PiiFinding]
        Detected PII keyword and/or proper-name matches.
    """
    snip_width = 8
    findings: list[PiiFinding] = []

    for idx, pattern in _PII_WORD_REGEXES:
        match = pattern.search(contents)
        if match is not None:
            start = max(0, match.start("word") - snip_width)
            end = min(len(contents), match.end("word") + snip_width)
            snippet = contents[start:end].strip()[:PII_SNIPPET_LENGTH]
            findings.append(PiiFinding(pii_word_id=idx, snippet=snippet))

    if use_ner:
        ner_finding = _detect_proper_names_nltk(contents)
        if ner_finding is not None:
            findings.append(ner_finding)

    return findings


# ---------------------------------------------------------------------------
# Supporting routines (alphabetical)
# ---------------------------------------------------------------------------


def count_pii_name_matches(path: str | None, fname: str | None) -> int:
    """Count PII keyword matches appearing in a path and/or filename.

    Parameters
    ----------
    path
        Directory path string.
    fname
        Filename string (optional).

    Returns
    -------
    int
        Number of regex keyword matches found.
    """
    combined = f"{path or ''} {fname or ''}"
    return len(_PII_NAME_REGEX.findall(combined))


def extract_file_text(
    path: str | pathlib.Path,
    max_rows: int = 10,
    max_bytes: int = MAX_PII_FILE_BYTES,
) -> str:
    """Read up to *max_rows* of text from a supported text or Excel file.

    Parameters
    ----------
    path
        Path to the file to read.
    max_rows
        Maximum lines (text/CSV) or rows per worksheet (Excel) to read.
    max_bytes
        Maximum file size in bytes eligible for content inspection (guards against
        oversized files and compressed spreadsheet zip bombs).

    Returns
    -------
    str
        Concatenated text sample, or an empty string if unsupported or unreadable.
    """
    file_path = pathlib.Path(path)
    suffix = file_path.suffix.lower()
    if suffix not in _TEXT_EXTENSIONS and suffix not in _EXCEL_EXTENSIONS:
        return ""

    try:
        st = file_path.lstat()
        if st.st_size > max_bytes:
            logger.debug(
                "Skipping PII content scan for oversized file {} ({} bytes > {} limit).",
                file_path,
                st.st_size,
                max_bytes,
            )
            return ""
    except OSError as exc:
        logger.debug("Could not stat file {}: {}", file_path, exc)
        return ""

    if suffix in _TEXT_EXTENSIONS:
        try:
            lines: list[str] = []
            with open_read_noatime(
                file_path, binary=False, encoding="utf-8", errors="ignore"
            ) as handle:
                for _ in range(max_rows):
                    line = handle.readline(MAX_PII_LINE_BYTES)
                    if not line:
                        break
                    lines.append(line.strip())
            return " ".join(lines)
        except OSError as exc:
            logger.debug("Could not read text file {}: {}", file_path, exc)
            return ""

    if suffix in _EXCEL_EXTENSIONS:
        try:
            with open_read_noatime(file_path, binary=True) as handle:
                wb = openpyxl.load_workbook(handle, read_only=True, data_only=True)
                try:
                    chunks: list[str] = []
                    for sheet in wb.worksheets:
                        for row_idx, row in enumerate(sheet.iter_rows(values_only=True)):
                            if row_idx >= max_rows:
                                break
                            for val in row:
                                if val is not None:
                                    chunks.append(str(val))
                    return " ".join(chunks)
                finally:
                    wb.close()
        except Exception as exc:
            logger.debug("Could not read Excel file {}: {}", file_path, exc)
            return ""

    return ""


def _detect_proper_names_nltk(contents: str) -> PiiFinding | None:
    """Run optional NLTK PERSON NER without triggering network downloads."""
    try:
        nltk = importlib.import_module("nltk")
    except ImportError:
        logger.debug("Optional package 'nltk' not installed; skipping NER PII detection.")
        return None

    try:
        tokens = nltk.word_tokenize(contents)
        tags = nltk.pos_tag(tokens)
        proper_nouns = [tag for tag in tags if tag[1] == "NNP"]
        if not proper_nouns:
            return None
        tree = nltk.ne_chunk(proper_nouns)
        people = list(tree.subtrees(filter=lambda t: t.label() == "PERSON"))
        if not people:
            return None
        snippet_parts: list[str] = []
        for person in people:
            snippet_parts.append(" ".join(token for token, _pos in person.leaves()))
            if len(" ".join(snippet_parts)) >= PII_SNIPPET_LENGTH:
                break
        snippet = " ".join(snippet_parts).strip()[:PII_SNIPPET_LENGTH]
        return PiiFinding(
            pii_word_id=PII_KEYWORDS.index(PII_PROPER_NAME_LABEL),
            snippet=snippet,
        )
    except LookupError:
        logger.debug("NLTK data corpora unavailable locally; skipping NER PII detection.")
        return None
    except Exception as exc:
        logger.debug("NLTK NER detection skipped due to error: {}", exc)
        return None
