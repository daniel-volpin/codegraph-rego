import logging
import os
import shutil
import stat
import zipfile

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class UploadValidationError(ValueError):
    """Raised when an uploaded archive violates validation limits."""


def _is_symlink_member(member: zipfile.ZipInfo) -> bool:
    """True when a zip entry's mode bits mark it as a symbolic link.

    Symlink members are a Zip-Slip vector: a malicious archive can write a
    symlink (e.g. ``link -> /``) and then a later entry whose path traverses
    that link to escape the destination directory. We refuse to materialize any
    symlink, which removes the through-symlink escape entirely.
    """
    mode = member.external_attr >> 16
    return stat.S_ISLNK(mode)


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
    dest_root = os.path.realpath(dest_dir)
    allowed_exts = allowed_exts or []
    members = zip_file.infolist()
    if len(members) > max_entries:
        raise UploadValidationError(f"Archive contains too many entries ({len(members)} > {max_entries})")

    extracted_total = 0
    for member in members:
        if _is_symlink_member(member):
            logger.warning("Skipping symlink entry (Zip-Slip protection): %s", member.filename)
            continue
        member_path = os.path.realpath(os.path.join(dest_dir, member.filename))
        if not member_path.startswith(dest_root + os.sep) and member_path != dest_root:
            logger.warning("Skipping suspicious entry: %s", member.filename)
            continue
        if member.is_dir():
            os.makedirs(member_path, exist_ok=True)
        elif member_path == dest_root:
            # A non-directory entry that normalizes exactly to the destination
            # root would otherwise try to open the directory itself for writing.
            logger.warning("Skipping entry resolving to destination root: %s", member.filename)
            continue
        else:
            if member.file_size > max_file_size:
                logger.error("File %s exceeds size limit (%d bytes)", member.filename, member.file_size)
                raise UploadValidationError(f"File {member.filename} exceeds size limit")

            compressed_size = member.compress_size
            if compressed_size == 0:
                if member.file_size > 0:
                    raise UploadValidationError(f"File {member.filename} has an invalid compression ratio")
            else:
                compression_ratio = member.file_size / compressed_size
                if compression_ratio > max_compression_ratio:
                    raise UploadValidationError(
                        f"File {member.filename} exceeds compression ratio limit ({compression_ratio:.2f} > {max_compression_ratio})"
                    )

            ext = os.path.splitext(member.filename)[1].lower()
            if allowed_exts and ext not in allowed_exts:
                logger.warning("Skipping file with forbidden extension: %s", member.filename)
                continue

            extracted_total += member.file_size
            if extracted_total > max_total_size:
                raise UploadValidationError(
                    f"Archive exceeds total extracted size limit ({extracted_total} > {max_total_size})"
                )

            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            with zip_file.open(member, "r") as src, open(member_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            logger.debug("Extracted: %s", member.filename)


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
