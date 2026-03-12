# firmware-mcp

MCP server for firmware image extraction and analysis. Handles unpacking, binary inventory, security file discovery, version diffing, and entropy analysis.

## What it does

- **fw_extract** -- Unpack firmware images automatically using binwalk. Handles SquashFS, CramFS, JFFS2, CPIO, UBI, gzip, LZMA, XZ, and more. Detects architecture from extracted ELF headers.
- **fw_scan** -- Signature scan without extraction. Identifies embedded filesystems, compression types, and content offsets.
- **fw_list_binaries** -- Inventory all ELF binaries in an extracted filesystem. Categorizes by function (CGI handlers, HTTP daemons, remote access services, SUID binaries, UPnP, SMB, DNS) with architecture and size info.
- **fw_find_interesting** -- Quick security scan of extracted firmware. Finds hardcoded credentials (passwd/shadow), SSH keys baked into firmware, SSL/TLS private keys, config files containing secrets, CGI scripts, startup scripts, SUID binaries.
- **fw_diff_versions** -- Compare two firmware versions side by side. Reports added, removed, and modified files with size deltas. Prioritizes changed binaries and security-relevant files.
- **fw_entropy** -- Shannon entropy analysis to detect encrypted or compressed regions. Produces an ASCII entropy map and identifies high-entropy blocks.

## Requirements

- Python 3.10+
- [binwalk](https://github.com/ReFirmLabs/binwalk) installed and in PATH
- Dependencies: `pip install -r requirements.txt`

## Setup

```bash
pip install -r requirements.txt
python server.py
```

## Security

- Output directory validation prevents path traversal during extraction
- Post-extraction symlink escape check removes symlinks pointing outside the output directory (Zip-Slip mitigation)
- File size limit of 2 GB
- Set `FIRMWARE_ALLOWED_DIRS` environment variable to restrict where extracted files can be written

## Architecture

```
firmware/
  server.py              # MCP server, all tools and helpers
```

Standalone single-file server. ELF header parsing is done natively without external tools. File hashing uses SHA-256 for diffing.

## License

CC BY-NC-SA 4.0 -- see [LICENSE](LICENSE).
