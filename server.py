"""Firmware Extraction MCP Server - Extract, analyze, and diff firmware images.

Usage:
    python server.py
"""

import sys
import os
import subprocess
import struct
import hashlib
import math
import json
import re
import glob as glob_mod

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastmcp import FastMCP

mcp = FastMCP(
    "firmware",
    instructions=(
        "Firmware extraction and analysis tools for reverse engineering.\n"
        "Tools for extracting firmware images, listing binaries, finding security-relevant files,\n"
        "comparing firmware versions, and analyzing entropy.\n\n"
        "Typical workflow:\n"
        "1. fw_scan to identify firmware contents\n"
        "2. fw_extract to unpack the firmware\n"
        "3. fw_list_binaries to inventory all ELF files\n"
        "4. fw_find_interesting to find security-relevant files\n"
        "5. Load interesting binaries into Ghidra/radare2 for deep analysis"
    ),
)


def _check_binwalk() -> tuple[bool, str]:
    """Check if binwalk is available."""
    try:
        result = subprocess.run(["binwalk", "--help"], capture_output=True, timeout=5)
        return True, ""
    except FileNotFoundError:
        return False, "binwalk not found. Install with: pip install binwalk"
    except Exception as e:
        return False, f"binwalk check failed: {e}"


MAX_CONFIG_SCANS = 500  # Don't read more than 500 config files
MAX_FIRMWARE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
MIN_ENTROPY_BLOCK_SIZE = 256  # bytes
MAX_ENTROPY_BLOCKS = 10000

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_output_dir(output_dir: str, firmware_path: str) -> tuple[bool, str]:
    """Validate output_dir against allowed directories to prevent path traversal.

    If FIRMWARE_ALLOWED_DIRS env var is set (comma-separated), output_dir must
    fall under one of those directories.  Otherwise, output_dir must be under
    the same parent directory as the firmware file.
    """
    resolved = os.path.realpath(output_dir)
    allowed_env = os.environ.get("FIRMWARE_ALLOWED_DIRS", "").strip()
    if allowed_env:
        allowed_dirs = [os.path.realpath(d.strip()) for d in allowed_env.split(",") if d.strip()]
        for allowed in allowed_dirs:
            if resolved == allowed or resolved.startswith(allowed + os.sep):
                return True, ""
        return False, (
            f"Error: Output directory '{resolved}' is not under any allowed directory. "
            f"Allowed: {', '.join(allowed_dirs)}"
        )
    else:
        firmware_parent = os.path.realpath(os.path.dirname(os.path.abspath(firmware_path)))
        if resolved == firmware_parent or resolved.startswith(firmware_parent + os.sep):
            return True, ""
        return False, (
            f"Error: Output directory '{resolved}' must be under the firmware's parent directory "
            f"'{firmware_parent}'. Set FIRMWARE_ALLOWED_DIRS env var to allow other locations."
        )


def _check_symlink_escape(output_dir: str) -> list[str]:
    """Walk output_dir after extraction and remove any symlinks that escape it.

    Returns list of removed symlink paths (for logging/reporting).
    """
    resolved_base = os.path.realpath(output_dir)
    removed = []
    for root, dirs, files in os.walk(output_dir):
        for name in files + dirs:
            fpath = os.path.join(root, name)
            if os.path.islink(fpath):
                target = os.path.realpath(fpath)
                if not (target == resolved_base or target.startswith(resolved_base + os.sep)):
                    try:
                        os.remove(fpath)
                    except OSError:
                        pass
                    removed.append(fpath)
    return removed


def _check_file_size(path: str) -> tuple[bool, str]:
    """Reject files exceeding MAX_FIRMWARE_SIZE."""
    try:
        size = os.path.getsize(path)
        if size > MAX_FIRMWARE_SIZE:
            return False, (
                f"Error: File size ({size:,} bytes) exceeds maximum allowed "
                f"({MAX_FIRMWARE_SIZE:,} bytes / 2 GB)."
            )
        return True, ""
    except OSError as e:
        return False, f"Error: Cannot stat file: {e}"

def _read_elf_header(path: str) -> dict | None:
    """Read ELF header to get arch/bits/endian without external tools."""
    try:
        # Skip tiny files (ELF header is at least 16 bytes)
        if os.path.getsize(path) < 20:
            return None
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"\x7fELF":
                return None
            ei_class = struct.unpack("B", f.read(1))[0]  # 1=32bit, 2=64bit
            ei_data = struct.unpack("B", f.read(1))[0]  # 1=LE, 2=BE
            f.read(1)  # EI_VERSION
            f.read(1)  # EI_OSABI
            f.read(8)  # padding
            fmt = "<H" if ei_data == 1 else ">H"
            e_type = struct.unpack(fmt, f.read(2))[0]
            e_machine = struct.unpack(fmt, f.read(2))[0]

            machines = {
                3: "x86",
                8: "MIPS",
                40: "ARM",
                62: "x86_64",
                183: "ARM64",
                243: "RISC-V",
            }
            arch = machines.get(e_machine, f"unknown({e_machine})")
            bits = 64 if ei_class == 2 else 32
            endian = "LE" if ei_data == 1 else "BE"
            types = {2: "EXEC", 3: "DYN (shared lib)"}
            elf_type = types.get(e_type, f"type({e_type})")

            return {"arch": arch, "bits": bits, "endian": endian, "type": elf_type}
    except Exception:
        return None


def _hash_file(path: str) -> str | None:
    """SHA-256 hash (first 16 hex chars) of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def fw_extract(firmware_path: str, output_dir: str = "") -> str:
    """Extract a firmware image automatically.

    Auto-detects format via binwalk signature scan. Handles squashfs, cramfs,
    jffs2, cpio, gzip, xz, lzma, ubi, and more.

    Args:
        firmware_path: Path to the firmware image file.
        output_dir: Where to extract. If empty, creates <firmware>_extracted/ next to the file.

    Returns:
        Extraction results including list of extracted files, filesystem type, and architecture hints.
    """
    if not os.path.exists(firmware_path):
        return f"Error: File not found: {firmware_path}"

    # File size check
    ok, err = _check_file_size(firmware_path)
    if not ok:
        return err

    if not output_dir:
        base = os.path.splitext(firmware_path)[0]
        output_dir = f"{base}_extracted"

    # Path traversal check
    ok, err = _validate_output_dir(output_dir, firmware_path)
    if not ok:
        return err

    os.makedirs(output_dir, exist_ok=True)

    # Check binwalk availability
    available, err_msg = _check_binwalk()
    if not available:
        return f"Error: {err_msg}"

    # Try binwalk first
    try:
        result = subprocess.run(
            ["binwalk", "-e", "-C", output_dir, firmware_path],
            capture_output=True,
            text=True,
            timeout=300,
        )
        binwalk_output = result.stdout
    except subprocess.TimeoutExpired:
        return "Error: binwalk extraction timed out after 300 seconds."

    # Post-extraction symlink escape check (Zip-Slip mitigation)
    escaped_links = _check_symlink_escape(output_dir)

    # Collect extracted contents
    extracted_files = []
    total_size = 0
    arch_hints = set()
    fs_types = set()

    for root, dirs, files in os.walk(output_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, output_dir).replace("\\", "/")
            size = 0
            try:
                size = os.path.getsize(fpath)
            except OSError:
                pass
            total_size += size
            extracted_files.append(rel)

            # Architecture hints from ELF binaries
            elf = _read_elf_header(fpath)
            if elf:
                arch_hints.add(f"{elf['arch']} {elf['bits']}bit {elf['endian']}")

            # Filesystem type hints
            lower = rel.lower()
            if "squashfs" in lower:
                fs_types.add("SquashFS")
            elif "cramfs" in lower:
                fs_types.add("CramFS")
            elif "jffs2" in lower:
                fs_types.add("JFFS2")
            elif "cpio" in lower:
                fs_types.add("CPIO")
            elif "ubifs" in lower or "ubi" in lower:
                fs_types.add("UBIFS")

    # Build report
    parts = [
        f"## Extraction Results\n",
        f"- Firmware: {firmware_path}",
        f"- Output: {output_dir}",
        f"- Files extracted: {len(extracted_files)}",
        f"- Total size: {total_size:,} bytes",
    ]

    if fs_types:
        parts.append(f"- Filesystem types: {', '.join(sorted(fs_types))}")
    if arch_hints:
        parts.append(f"- Architecture: {', '.join(sorted(arch_hints))}")

    parts.append("")

    if binwalk_output:
        parts.append("### Binwalk Output")
        parts.append(f"```\n{binwalk_output.strip()}\n```")
        parts.append("")

    # Show directory structure (top-level only)
    if extracted_files:
        parts.append("### Top-level contents")
        top_level = set()
        for f in extracted_files:
            top_level.add(f.split("/")[0])
        for item in sorted(top_level)[:30]:
            parts.append(f"- {item}")
        if len(top_level) > 30:
            parts.append(f"- ... and {len(top_level) - 30} more")

    if escaped_links:
        parts.append("")
        parts.append(f"### WARNING: {len(escaped_links)} symlink(s) escaped output directory (removed)")
        for link in escaped_links[:10]:
            parts.append(f"- {link}")
        if len(escaped_links) > 10:
            parts.append(f"- ... and {len(escaped_links) - 10} more")

    return "\n".join(parts)


@mcp.tool()
def fw_scan(firmware_path: str) -> str:
    """Scan a firmware image without extracting -- show signatures, offsets, and content types.

    Args:
        firmware_path: Path to the firmware image file.

    Returns:
        Binwalk signature scan results.
    """
    if not os.path.exists(firmware_path):
        return f"Error: File not found: {firmware_path}"

    # File size check
    ok, err = _check_file_size(firmware_path)
    if not ok:
        return err

    # Check binwalk availability
    available, err_msg = _check_binwalk()
    if not available:
        return f"Error: {err_msg}"

    try:
        result = subprocess.run(
            ["binwalk", firmware_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout.strip()
        if not output:
            return f"No signatures found in {firmware_path}. File may be encrypted or unknown format."

        # Detect compression types
        compressions = set()
        for line in output.splitlines():
            lower = line.lower()
            for comp_type in ["gzip", "lzma", "xz", "zlib", "lzo", "bzip2", "lz4", "zstd"]:
                if comp_type in lower:
                    compressions.add(comp_type)
        if compressions:
            output += f"\n\nDetected compression: {', '.join(sorted(compressions))}"

        return f"Firmware scan results for {os.path.basename(firmware_path)}:\n\n{output}"
    except subprocess.TimeoutExpired:
        return "Error: binwalk scan timed out after 60 seconds."


@mcp.tool()
def fw_list_binaries(rootfs_path: str, format: str = "default") -> str:
    """List all ELF binaries in an extracted firmware filesystem with metadata.

    Categorizes binaries by function (CGI, HTTP daemon, remote access, SUID, etc.)
    and provides architecture info parsed directly from ELF headers.

    Args:
        rootfs_path: Path to extracted root filesystem (e.g. squashfs-root/).
        format: "default" for grouped text, "report" for markdown table.

    Returns:
        Categorized binary inventory with arch, size, and SUID info.
    """
    if not os.path.isdir(rootfs_path):
        return f"Error: Directory not found: {rootfs_path}"

    binaries = []

    for root, dirs, files in os.walk(rootfs_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            elf_info = _read_elf_header(fpath)
            if not elf_info:
                continue

            rel_path = os.path.relpath(fpath, rootfs_path).replace("\\", "/")
            try:
                st = os.stat(fpath)
                size = st.st_size
                is_suid = bool(st.st_mode & 0o4000)
            except OSError:
                size = 0
                is_suid = False

            # Categorize
            category = "other"
            rel_lower = rel_path.lower()
            if "cgi" in rel_lower:
                category = "CGI"
            elif any(
                p in rel_lower
                for p in ["httpd", "lighttpd", "uhttpd", "nginx", "thttpd", "goahead"]
            ):
                category = "HTTP daemon"
            elif any(p in rel_lower for p in ["sshd", "dropbear", "telnetd"]):
                category = "Remote access"
            elif any(p in rel_lower for p in ["upnp", "ssdp", "miniupnpd"]):
                category = "UPnP"
            elif any(p in rel_lower for p in ["smb", "nmbd", "samba"]):
                category = "SMB"
            elif any(p in rel_lower for p in ["dnsmasq", "named"]):
                category = "DNS"
            elif is_suid:
                category = "SUID"
            elif any(d in rel_lower for d in ["sbin/", "usr/sbin/"]):
                category = "System daemon"

            binaries.append(
                {
                    "path": rel_path,
                    "arch": f"{elf_info['arch']} {elf_info['bits']}bit {elf_info['endian']}",
                    "type": elf_info["type"],
                    "size": size,
                    "suid": is_suid,
                    "category": category,
                }
            )

    if not binaries:
        return f"No ELF binaries found in {rootfs_path}"

    # Sort: interesting categories first, then by size descending
    category_order = {
        "CGI": 0,
        "HTTP daemon": 1,
        "UPnP": 2,
        "Remote access": 3,
        "SUID": 4,
        "System daemon": 5,
        "SMB": 6,
        "DNS": 7,
        "other": 99,
    }
    binaries.sort(key=lambda b: (category_order.get(b["category"], 50), -b["size"]))

    if format == "report":
        lines = [
            f"### Firmware Binary Inventory ({len(binaries)} ELF files)\n",
            "| Category | Path | Arch | Size | SUID |",
            "|----------|------|------|------|------|",
        ]
        for b in binaries:
            suid = "SUID" if b["suid"] else ""
            size_str = (
                f"{b['size']:,}"
                if b["size"] < 1048576
                else f"{b['size'] / 1048576:.1f} MB"
            )
            lines.append(
                f"| {b['category']} | `{b['path']}` | {b['arch']} | {size_str} | {suid} |"
            )
        return "\n".join(lines)

    # Default format
    lines = [f"Binary inventory ({len(binaries)} ELF files in {rootfs_path}):\n"]
    current_cat = None
    for b in binaries:
        if b["category"] != current_cat:
            current_cat = b["category"]
            lines.append(f"\n[{current_cat}]")
        suid = " [SUID]" if b["suid"] else ""
        size_str = (
            f"{b['size']:,}B"
            if b["size"] < 1048576
            else f"{b['size'] / 1048576:.1f}MB"
        )
        lines.append(
            f"  {b['path']:<50} {b['arch']:<20} {size_str:>10}{suid}"
        )
    return "\n".join(lines)


@mcp.tool()
def fw_find_interesting(rootfs_path: str) -> str:
    """Quick-scan for security-relevant files in a firmware filesystem.

    Looks for hardcoded credentials, SSH keys, SSL certs/keys, config files
    with secrets, CGI scripts, startup scripts, and more.

    Args:
        rootfs_path: Path to extracted root filesystem.

    Returns:
        Categorized list of security-relevant files with previews where applicable.
    """
    if not os.path.isdir(rootfs_path):
        return f"Error: Directory not found: {rootfs_path}"

    findings = {
        "credentials": [],
        "crypto": [],
        "suid": [],
        "configs": [],
        "web": [],
        "startup": [],
        "world_writable": [],
    }

    config_scans = 0

    for root, dirs, files in os.walk(rootfs_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, rootfs_path).replace("\\", "/")

            # Credentials
            if fname in ("passwd", "shadow", "shadow-"):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read(4096)
                    findings["credentials"].append(
                        {"path": rel, "preview": content[:200]}
                    )
                except Exception:
                    pass

            # SSH keys in firmware = hardcoded
            if (
                fname.startswith("dropbear_")
                or fname.endswith("_key")
                or fname == "authorized_keys"
                or fname in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
            ):
                findings["crypto"].append(
                    {"path": rel, "type": "SSH key (hardcoded in firmware!)"}
                )

            # SSL certs/keys
            if fname.endswith((".pem", ".crt", ".key", ".p12")):
                kind = (
                    "private key" if fname.endswith(".key") else "certificate/key material"
                )
                findings["crypto"].append({"path": rel, "type": f"SSL/TLS {kind}"})

            # Web content
            if "cgi" in rel.lower() or fname.endswith(
                (".cgi", ".php", ".asp", ".lua", ".sh")
            ):
                if "cgi" in rel.lower() or fname.endswith((".cgi", ".php", ".asp")):
                    findings["web"].append({"path": rel})

            # Config files - scan for secrets
            if fname.endswith(
                (".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml")
            ):
                if config_scans >= MAX_CONFIG_SCANS:
                    continue
                config_scans += 1
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read(8192)
                    for pattern in [
                        "password",
                        "passwd",
                        "secret",
                        "token",
                        "api_key",
                        "private",
                    ]:
                        if pattern in content.lower():
                            for line in content.split("\n"):
                                if pattern in line.lower() and len(line.strip()) > 5:
                                    findings["configs"].append(
                                        {"path": rel, "match": line.strip()[:100]}
                                    )
                                    break
                            break
                except Exception:
                    pass

            # Startup scripts
            if "init.d" in rel or "rc.d" in rel or "rcS.d" in rel:
                findings["startup"].append({"path": rel})

            # SUID binaries
            try:
                mode = os.stat(fpath).st_mode
                if mode & 0o4000:
                    findings["suid"].append({"path": rel})
            except Exception:
                pass

    # Format output
    parts = [f"## Security-Relevant Files in {rootfs_path}\n"]

    if findings["credentials"]:
        parts.append(f"### Credentials ({len(findings['credentials'])})")
        for f in findings["credentials"]:
            parts.append(f"- `{f['path']}`")
            if f.get("preview"):
                parts.append(f"  ```\n  {f['preview'][:150]}\n  ```")
        parts.append("")

    if findings["crypto"]:
        parts.append(f"### Crypto Material ({len(findings['crypto'])})")
        for f in findings["crypto"]:
            parts.append(f"- `{f['path']}` -- {f['type']}")
        parts.append("")

    if findings["suid"]:
        parts.append(f"### SUID Binaries ({len(findings['suid'])})")
        for f in findings["suid"]:
            parts.append(f"- `{f['path']}`")
        parts.append("")

    if findings["web"]:
        parts.append(f"### Web/CGI ({len(findings['web'])})")
        for f in findings["web"]:
            parts.append(f"- `{f['path']}`")
        parts.append("")

    if findings["configs"]:
        parts.append(f"### Config Files with Secrets ({len(findings['configs'])})")
        for f in findings["configs"]:
            parts.append(f"- `{f['path']}`: `{f['match']}`")
        parts.append("")

    if findings["startup"]:
        parts.append(f"### Startup Scripts ({len(findings['startup'])})")
        for f in findings["startup"][:20]:
            parts.append(f"- `{f['path']}`")
        if len(findings["startup"]) > 20:
            parts.append(f"- ... and {len(findings['startup']) - 20} more")
        parts.append("")

    total = sum(len(v) for v in findings.values())
    parts.append(f"\n**Total: {total} security-relevant files found.**")
    return "\n".join(parts)


@mcp.tool()
def fw_diff_versions(old_rootfs: str, new_rootfs: str) -> str:
    """Compare two firmware filesystem versions to find what changed.

    Lists new, removed, and modified binaries with size changes.
    Highlights changed CGIs and daemons for security review.

    Args:
        old_rootfs: Path to the older firmware root filesystem.
        new_rootfs: Path to the newer firmware root filesystem.

    Returns:
        Diff report with added, removed, and modified files.
    """
    for path, label in [(old_rootfs, "Old"), (new_rootfs, "New")]:
        if not os.path.isdir(path):
            return f"Error: {label} directory not found: {path}"

    def scan_fs(rootfs):
        files = {}
        for root, dirs, fnames in os.walk(rootfs):
            for fname in fnames:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, rootfs).replace("\\", "/")
                try:
                    size = os.path.getsize(fpath)
                except OSError:
                    size = 0
                files[rel] = {
                    "size": size,
                    "hash": _hash_file(fpath),
                    "full_path": fpath,
                }
        return files

    old_files = scan_fs(old_rootfs)
    new_files = scan_fs(new_rootfs)

    added = set(new_files.keys()) - set(old_files.keys())
    removed = set(old_files.keys()) - set(new_files.keys())
    common = set(old_files.keys()) & set(new_files.keys())

    modified = []
    for f in common:
        if old_files[f]["hash"] != new_files[f]["hash"]:
            modified.append(
                {
                    "path": f,
                    "old_size": old_files[f]["size"],
                    "new_size": new_files[f]["size"],
                    "size_diff": new_files[f]["size"] - old_files[f]["size"],
                }
            )

    modified.sort(key=lambda x: abs(x["size_diff"]), reverse=True)

    parts = [
        f"## Firmware Diff\n",
        f"- Old: {old_rootfs}",
        f"- New: {new_rootfs}",
        f"- Files: {len(old_files)} -> {len(new_files)}",
        f"- Added: {len(added)}, Removed: {len(removed)}, Modified: {len(modified)}",
        "",
    ]

    if modified:
        parts.append(f"### Modified Files ({len(modified)})")
        # Show ELF binaries first
        elf_modified = [
            m
            for m in modified
            if _read_elf_header(os.path.join(new_rootfs, m["path"]))
        ]
        if elf_modified:
            parts.append("\n**Changed Binaries (prioritized):**")
            for m in elf_modified[:30]:
                diff_str = (
                    f"+{m['size_diff']}" if m["size_diff"] > 0 else str(m["size_diff"])
                )
                parts.append(
                    f"- `{m['path']}` ({m['old_size']:,} -> {m['new_size']:,}, {diff_str} bytes)"
                )

        non_elf = [m for m in modified if m not in elf_modified]
        if non_elf:
            parts.append(f"\n**Other changed files:** {len(non_elf)}")
            for m in non_elf[:20]:
                parts.append(f"- `{m['path']}`")
        parts.append("")

    if added:
        parts.append(f"### Added Files ({len(added)})")
        for f in sorted(added)[:30]:
            parts.append(f"- `{f}`")
        if len(added) > 30:
            parts.append(f"- ... and {len(added) - 30} more")
        parts.append("")

    if removed:
        parts.append(f"### Removed Files ({len(removed)})")
        for f in sorted(removed)[:30]:
            parts.append(f"- `{f}`")
        if len(removed) > 30:
            parts.append(f"- ... and {len(removed) - 30} more")

    return "\n".join(parts)


@mcp.tool()
def fw_entropy(firmware_path: str, block_size: int = 4096) -> str:
    """Analyze entropy of a firmware image to detect encrypted/compressed regions.

    High entropy (>7.5) typically indicates encryption or compression.
    Low entropy (<1.0) indicates padding or empty space.

    Args:
        firmware_path: Path to the firmware image file.
        block_size: Size of each analysis block in bytes (default: 4096).

    Returns:
        Entropy statistics, high/low entropy regions, and a visual entropy map.
    """
    if not os.path.exists(firmware_path):
        return f"Error: File not found: {firmware_path}"

    # File size check
    ok, err = _check_file_size(firmware_path)
    if not ok:
        return err

    # Enforce minimum block_size to prevent OOM
    if block_size < MIN_ENTROPY_BLOCK_SIZE:
        block_size = MIN_ENTROPY_BLOCK_SIZE

    # Auto-increase block_size if too many blocks would be created
    file_size = os.path.getsize(firmware_path)
    if file_size // block_size > MAX_ENTROPY_BLOCKS:
        block_size = file_size // MAX_ENTROPY_BLOCKS
        # Align to 256 bytes
        block_size = ((block_size + 255) // 256) * 256

    results = []
    try:
        with open(firmware_path, "rb") as f:
            offset = 0
            while True:
                block = f.read(block_size)
                if not block or len(block) < 256:
                    break
                # Calculate Shannon entropy
                counts = [0] * 256
                for b in block:
                    counts[b] += 1
                entropy = 0.0
                for c in counts:
                    if c > 0:
                        p = c / len(block)
                        entropy -= p * math.log2(p)
                results.append({"offset": offset, "entropy": round(entropy, 3)})
                offset += block_size
    except Exception as e:
        return f"Error reading file: {e}"

    if not results:
        return "No data to analyze (file too small)."

    avg_entropy = sum(r["entropy"] for r in results) / len(results)
    max_e = max(results, key=lambda r: r["entropy"])
    min_e = min(results, key=lambda r: r["entropy"])

    # Find high-entropy regions (likely encrypted/compressed)
    high_regions = []
    in_high = False
    region_start = 0
    for r in results:
        if r["entropy"] > 7.5 and not in_high:
            in_high = True
            region_start = r["offset"]
        elif r["entropy"] <= 7.5 and in_high:
            in_high = False
            high_regions.append(
                {
                    "start": region_start,
                    "end": r["offset"],
                    "size": r["offset"] - region_start,
                }
            )
    if in_high:
        high_regions.append(
            {"start": region_start, "end": offset, "size": offset - region_start}
        )

    # Find low-entropy regions (likely padding/empty)
    low_regions = [r for r in results if r["entropy"] < 1.0]

    file_size = os.path.getsize(firmware_path)
    parts = [
        f"## Entropy Analysis: {os.path.basename(firmware_path)}\n",
        f"- File size: {file_size:,} bytes",
        f"- Block size: {block_size:,} bytes",
        f"- Blocks analyzed: {len(results)}",
        f"- Average entropy: {avg_entropy:.3f} / 8.0",
        f"- Min entropy: {min_e['entropy']} at offset 0x{min_e['offset']:x}",
        f"- Max entropy: {max_e['entropy']} at offset 0x{max_e['offset']:x}",
        "",
    ]

    if high_regions:
        parts.append(
            f"### High Entropy Regions ({len(high_regions)}) -- likely encrypted/compressed"
        )
        for r in high_regions:
            parts.append(
                f"- 0x{r['start']:08x} - 0x{r['end']:08x} ({r['size']:,} bytes)"
            )
        parts.append("")

    if low_regions:
        parts.append(
            f"### Low Entropy Regions ({len(low_regions)} blocks) -- likely padding/empty"
        )
        parts.append("")

    # ASCII entropy map
    parts.append("### Entropy Map (each char = 1 block)")
    line = ""
    for r in results:
        e = r["entropy"]
        if e < 1.0:
            c = "."
        elif e < 3.0:
            c = "_"
        elif e < 5.0:
            c = "o"
        elif e < 7.0:
            c = "#"
        elif e < 7.5:
            c = "@"
        else:
            c = "E"  # encrypted/compressed
        line += c
        if len(line) >= 80:
            parts.append(f"  {line}")
            line = ""
    if line:
        parts.append(f"  {line}")
    parts.append(
        "\n  Legend: .=empty _=low o=mid #=high @=very high E=encrypted/compressed"
    )

    return "\n".join(parts)


if __name__ == "__main__":
    mcp.run()
