import os
import zipfile
import shutil
import logging
from typing import Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


def safe_extract_zip(
    zip_file: zipfile.ZipFile,
    dest_dir: str,
    max_file_size: int = 50 * 1024 * 1024,
    allowed_exts: Optional[list[str]] = None,
) -> None:
    """
    Safely extract a ZIP to dest_dir, preventing Zip Slip path traversal and enforcing file size/type limits.
    Args:
        zip_file: Opened zipfile.ZipFile object.
        dest_dir: Destination directory for extraction.
        max_file_size: Maximum allowed file size in bytes (default 50MB).
        allowed_exts: List of allowed file extensions (e.g., ['.java', '.kt', '.xml']). If None, allow all.
    Raises:
        ValueError: If a file exceeds size limit or has a forbidden extension.
    """
    dest_root = os.path.realpath(dest_dir)
    allowed_exts = allowed_exts or []
    for member in zip_file.infolist():
        member_path = os.path.realpath(os.path.join(dest_dir, member.filename))
        if not member_path.startswith(dest_root + os.sep) and member_path != dest_root:
            logger.warning(f"Skipping suspicious entry: {member.filename}")
            continue
        if member.is_dir():
            os.makedirs(member_path, exist_ok=True)
        else:
            # Security: file size limit
            if member.file_size > max_file_size:
                logger.error(f"File {member.filename} exceeds size limit ({member.file_size} bytes)")
                raise ValueError(f"File {member.filename} exceeds size limit")
            # Security: extension check
            ext = os.path.splitext(member.filename)[1].lower()
            if allowed_exts and ext not in allowed_exts:
                logger.warning(f"Skipping file with forbidden extension: {member.filename}")
                continue
            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            with zip_file.open(member, "r") as src, open(member_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            # Only log extraction at debug level
            logger.debug(f"Extracted: {member.filename}")


def find_java_root(base: str) -> Optional[str]:
    """
    Locate a Java source root (src/main/java) within the uploaded folder.
    Args:
        base: Base directory to search.
    Returns:
        Path to Java root if found, else None.
    """
    for root, dirs, files in os.walk(base):
        if root.replace(os.sep, "/").endswith("src/main/java"):
            logger.debug(f"Java root found: {root}")
            return root
    logger.warning("No Java root found; using base directory.")
    return None
