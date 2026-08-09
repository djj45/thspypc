# BlockUpdate baseline 204655

This directory is an exact content snapshot of the system-block cache downloaded
by the official Windows client on 2026-08-10 (Asia/Shanghai).

- Source directory: `C:\同花顺软件\同花顺\BlockUpdate`
- Manifest: `_entries`
- Manifest version: `204655`
- Payload: 58 `block_*.ini`/`block_tree.ini` files, 3,000,907 bytes
- Snapshot total: 59 files, 3,002,950 bytes
- `_entries` SHA-256:
  `DB88F0CE18BB2F72A12E1CBBD2F70B6C7679B6085E220AB64988260AFE2BA053`
- Integrity result: all 58 payload files match the CRC32 recorded in `_entries`

The first value of every `[download_file_list]` entry is the unsigned CRC32 of
the complete file; the second value is that file's cloud version. Preserve this
snapshot unchanged: it is the old-side oracle for the next real incremental
update.

This fixture contains system block definitions only. It does not contain login
credentials, cookies, session IDs, packet captures, or HTTP logs.
