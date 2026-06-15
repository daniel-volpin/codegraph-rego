import logging
import os
import shutil
import stat
import zipfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class UploadValidationError(ValueError):
    """Raised when an uploaded archive violates validation limits."""


@dataclass(frozen=True)
class _ZipExtractionConfig:
    dest_dir: str
    dest_root: str
    allowed_extensions: set[str]
    max_file_size: int
    max_total_size: int
    max_compression_ratio: float


def _is_symlink_member(member: zipfile.ZipInfo) -> bool:
    """True if the entry is a symlink (a Zip-Slip vector we refuse to extract)."""
    return stat.S_ISLNK(member.external_attr >> 16)


def _resolve_member_path(dest_dir: str, filename: str) -> str:
    return os.path.realpath(os.path.join(dest_dir, filename))


def _is_within_destination(member_path: str, dest_root: str) -> bool:
    return member_path == dest_root or member_path.startswith(dest_root + os.sep)


def _extension_allowed(filename: str, allowed_exts: set[str]) -> bool:
    return not allowed_exts or os.path.splitext(filename)[1].lower() in allowed_exts


def _validate_member_size(member: zipfile.ZipInfo, max_file_size: int) -> None:
    if member.file_size <= max_file_size:
        return
    logger.error("File %s exceeds size limit (%d bytes)", member.filename, member.file_size)
    raise UploadValidationError(f"File {member.filename} exceeds size limit")


def _validate_compression_ratio(member: zipfile.ZipInfo, max_compression_ratio: float) -> None:
    if member.compress_size == 0:
        if member.file_size > 0:
            raise UploadValidationError(f"File {member.filename} has an invalid compression ratio")
        return

    compression_ratio = member.file_size / member.compress_size
    if compression_ratio > max_compression_ratio:
        raise UploadValidationError(
            f"File {member.filename} exceeds compression ratio limit "
            f"({compression_ratio:.2f} > {max_compression_ratio})"
        )


def _add_extracted_size(current_total: int, member: zipfile.ZipInfo, max_total_size: int) -> int:
    new_total = current_total + member.file_size
    if new_total > max_total_size:
        raise UploadValidationError(f"Archive exceeds total extracted size limit ({new_total} > {max_total_size})")
    return new_total


def _copy_member(zip_file: zipfile.ZipFile, member: zipfile.ZipInfo, member_path: str) -> None:
    os.makedirs(os.path.dirname(member_path), exist_ok=True)
    with zip_file.open(member, "r") as src, open(member_path, "wb") as dst:
        shutil.copyfileobj(src, dst)


def _extract_member(
    *,
    zip_file: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    config: _ZipExtractionConfig,
    extracted_total: int,
) -> int:
    if _is_symlink_member(member):
        logger.warning("Skipping symlink entry (Zip-Slip protection): %s", member.filename)
        return extracted_total

    member_path = _resolve_member_path(config.dest_dir, member.filename)
    if not _is_within_destination(member_path, config.dest_root):
        logger.warning("Skipping suspicious entry: %s", member.filename)
        return extracted_total

    if member.is_dir():
        os.makedirs(member_path, exist_ok=True)
        return extracted_total

    if member_path == config.dest_root:
        logger.warning("Skipping entry resolving to destination root: %s", member.filename)
        return extracted_total

    _validate_member_size(member, config.max_file_size)
    _validate_compression_ratio(member, config.max_compression_ratio)
    if not _extension_allowed(member.filename, config.allowed_extensions):
        logger.warning("Skipping file with forbidden extension: %s", member.filename)
        return extracted_total

    extracted_total = _add_extracted_size(extracted_total, member, config.max_total_size)
    _copy_member(zip_file, member, member_path)
    logger.debug("Extracted: %s", member.filename)
    return extracted_total


def safe_extract_zip(
    zip_file: zipfile.ZipFile,
    dest_dir: str,
    max_file_size: int = 50 * 1024 * 1024,
    max_total_size: int = 500 * 1024 * 1024,
    max_entries: int = 10_000,
    max_compression_ratio: float = 100.0,
    allowed_exts: list[str] | None = None,
) -> None:
    """
    Safely extract a ZIP to dest_dir, preventing Zip Slip path traversal and enforcing file size/type limits.
    Args:
        zip_file: Opened zipfile.ZipFile object.
        dest_dir: Destination directory for extraction.
        max_file_size: Maximum allowed file size in bytes (default 50MB).
        allowed_exts: List of allowed file extensions (e.g., ['.java', '.kt', '.xml']). If None, allow all.
    Raises:
        UploadValidationError: If the archive exceeds configured safety limits.
    """
    config = _ZipExtractionConfig(
        dest_dir=dest_dir,
        dest_root=os.path.realpath(dest_dir),
        allowed_extensions={ext.lower() for ext in (allowed_exts or [])},
        max_file_size=max_file_size,
        max_total_size=max_total_size,
        max_compression_ratio=max_compression_ratio,
    )
    members = zip_file.infolist()
    if len(members) > max_entries:
        raise UploadValidationError(f"Archive contains too many entries ({len(members)} > {max_entries})")

    extracted_total = 0
    for member in members:
        extracted_total = _extract_member(
            zip_file=zip_file,
            member=member,
            config=config,
            extracted_total=extracted_total,
        )


def find_java_roots(base: str) -> list[str]:
    """
    Locate all Java source roots (src/main/java) within the uploaded folder.
    Args:
        base: Base directory to search.
    Returns:
        Sorted absolute paths to Java roots.
    """
    roots: list[str] = []
    for root, dirs, files in os.walk(base):
        if root.replace(os.sep, "/").endswith("src/main/java"):
            logger.debug("Java root found: %s", root)
            roots.append(os.path.abspath(root))
    roots.sort(key=lambda path: os.path.relpath(path, base).replace(os.sep, "/"))
    if not roots:
        logger.warning("No Java roots found in uploaded archive.")
    return roots
