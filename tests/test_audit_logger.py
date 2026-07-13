"""Tests para audit_logger."""

import json
from crypto_toolkit.core.audit_logger import AuditLogger


def test_log_crea_registro(tmp_path):
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    record = logger.log("HASH", "test data", "COMPUTED")
    assert record["action"] == "HASH"
    assert record["result"] == "COMPUTED"


def test_leer_todos(tmp_path):
    log_path = tmp_path / "test_log.jsonl"
    logger = AuditLogger(str(log_path))
    logger.log("A1", "d1", "OK")
    logger.log("A2", "d2", "OK")
    assert len(logger.read_all()) == 2
