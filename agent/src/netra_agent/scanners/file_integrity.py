"""File Integrity and Hashing Scanner (SCAN_FILE_INTEGRITY)."""

import hashlib
from pathlib import Path
from typing import Any

from netra_shared.schemas.task import CapabilityEnum, FindingItem

from netra_agent.scanners.base import BaseScanner

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FILES_COUNT = 50


class FileIntegrityScanner(BaseScanner):
    """Defensive scanner for SHA-256 hashing of specified target files."""

    @property
    def capability(self) -> CapabilityEnum:
        return CapabilityEnum.SCAN_FILE_INTEGRITY

    def validate_parameters(self, parameters: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(parameters, dict):
            raise ValueError("Parameters must be a dictionary.")

        target_paths = parameters.get("paths")
        if not target_paths or not isinstance(target_paths, list):
            raise ValueError("Parameter 'paths' must be a non-empty list of file paths.")

        if len(target_paths) > MAX_FILES_COUNT:
            raise ValueError(f"Exceeded maximum file scan limit of {MAX_FILES_COUNT} files.")

        clean_paths = []
        for path_str in target_paths:
            if not isinstance(path_str, str):
                raise ValueError("Path items must be strings.")

            # Path Traversal & Shell Injection Check
            if any(char in path_str for char in (";", "|", "&", "`", "$", "\n")):
                raise ValueError(f"Illegal character in target path string '{path_str}'.")

            # Prevent scanning dangerous virtual / device files on Linux
            normalized_posix = path_str.replace("\\", "/").lower()
            if normalized_posix.startswith(("/proc", "/sys", "/dev")):
                raise ValueError(f"Path '{path_str}' targets forbidden system virtual filesystem.")

            # Resolve real absolute path
            p = Path(path_str).resolve()
            str_p = str(p)
            clean_paths.append(str_p)

        parameters["clean_paths"] = clean_paths
        return parameters

    def run_scan(
        self,
        parameters: dict[str, Any],
        task_id: str,
        execution_id: str,
    ) -> list[FindingItem]:
        findings: list[FindingItem] = []
        clean_paths: list[str] = parameters.get("clean_paths", [])

        hashed_files: list[dict[str, Any]] = []

        for path_str in clean_paths:
            p = Path(path_str)
            if not p.exists():
                findings.append(
                    FindingItem(
                        title=f"Target File Not Found ({p.name})",
                        category="FILE_INTEGRITY",
                        severity="LOW",
                        fingerprint=f"fp_fim_missing_{hashlib.sha256(path_str.encode()).hexdigest()[:12]}",
                        details={"path": path_str, "status": "NOT_FOUND"},
                    )
                )
                continue

            if not p.is_file():
                continue

            # File size limit check
            try:
                st = p.stat()
                file_size = st.st_size
                if file_size > MAX_FILE_SIZE_BYTES:
                    findings.append(
                        FindingItem(
                            title=f"File Exceeds Max Hash Size Limit ({p.name})",
                            category="FILE_INTEGRITY",
                            severity="INFORMATIONAL",
                            fingerprint=f"fp_fim_oversized_{hashlib.sha256(path_str.encode()).hexdigest()[:12]}",
                            details={
                                "path": path_str,
                                "size_bytes": file_size,
                                "limit_bytes": MAX_FILE_SIZE_BYTES,
                            },
                        )
                    )
                    continue

                # Compute SHA-256 hash safely without reading whole file into memory at once
                hasher = hashlib.sha256()
                with open(p, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)

                sha256_hash = hasher.hexdigest()

                hashed_files.append(
                    {
                        "path": path_str,
                        "sha256": sha256_hash,
                        "size_bytes": file_size,
                    }
                )

            except PermissionError:
                findings.append(
                    FindingItem(
                        title=f"Permission Denied Reading File ({p.name})",
                        category="FILE_INTEGRITY",
                        severity="LOW",
                        fingerprint=f"fp_fim_perm_{hashlib.sha256(path_str.encode()).hexdigest()[:12]}",
                        details={"path": path_str, "status": "PERMISSION_DENIED"},
                    )
                )

        findings.append(
            FindingItem(
                title=f"File Integrity Hashing Summary ({len(hashed_files)} Files)",
                category="FILE_INTEGRITY_SUMMARY",
                severity="INFORMATIONAL",
                fingerprint=f"fp_fim_sum_{task_id[:8]}",
                details={
                    "total_inspected": len(clean_paths),
                    "successfully_hashed_count": len(hashed_files),
                    "files": hashed_files,
                },
            )
        )

        return findings
