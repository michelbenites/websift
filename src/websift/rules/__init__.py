"""Importing this package registers every built-in rule."""

from . import crypto, exec, secrets, sql, webconf

__all__ = ["crypto", "exec", "secrets", "sql", "webconf"]
