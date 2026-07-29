"""Architecture guards for the thin THSClient facade."""
from __future__ import annotations

import ast
from pathlib import Path


MODULES = (
    "connection_primitives.py",
    "connection_runtime.py",
    "service_facade.py",
    "stock_cache.py",
)


def test_extracted_modules_do_not_import_or_store_client() -> None:
    package = Path(__file__).resolve().parents[1] / "src" / "thspypc"

    for name in MODULES:
        source = (package / name).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_modules = {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }

        assert "client" not in imported_modules
        assert "thspypc.client" not in imported_modules
        assert "thspypc.client" not in imported_names
        assert "self._client" not in source
