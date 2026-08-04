import json
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path

from fastapi import HTTPException

from backend.web.account_exports import build_account_auth_archive
from backend.web.application import (
    MAX_BATCH_ACCOUNT_IDS,
    _batch_account_ids,
    _find_account_auth_file,
    _load_account_auth_json,
    _stream_file,
)


class WebAuthJsonTests(unittest.TestCase):
    def test_batch_ids_validate_deduplicate_and_preserve_order(self):
        self.assertEqual(_batch_account_ids([3, 1, 3, 2]), [3, 1, 2])
        with self.assertRaisesRegex(HTTPException, "正整数"):
            _batch_account_ids([0])
        with self.assertRaisesRegex(HTTPException, f"最多操作 {MAX_BATCH_ACCOUNT_IDS}"):
            _batch_account_ids(list(range(1, MAX_BATCH_ACCOUNT_IDS + 2)))

    def test_loads_cpa_and_grok2api_json_from_configured_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cpa_dir = root / "cpa"
            g2a_dir = root / "g2a"
            cpa_dir.mkdir()
            g2a_dir.mkdir()
            cpa_path = cpa_dir / "xai-user@outlook.com.json"
            g2a_path = g2a_dir / "g2a-user@outlook.com.json"
            cpa_path.write_text(json.dumps({"type": "xai", "email": "user@outlook.com"}), encoding="utf-8")
            g2a_path.write_text(json.dumps({"accounts": [{"email": "user@outlook.com"}]}), encoding="utf-8")
            record = {
                "email": "user@outlook.com",
                "auth_info": (
                    "CPA 本地: /stale/root/xai-user@outlook.com.json\n"
                    "Grok2API: /stale/root/g2a-user@outlook.com.json"
                ),
            }
            config = {
                "cpa_auth_dir": str(cpa_dir),
                "grok2api_auth_dir": str(g2a_dir),
            }

            cpa = _load_account_auth_json(record, config, "cpa")
            g2a = _load_account_auth_json(record, config, "grok2api")
            self.assertEqual(Path(cpa["path"]), cpa_path)
            self.assertEqual(Path(g2a["path"]), g2a_path)
            self.assertEqual(json.loads(cpa["content"])["email"], "user@outlook.com")
            self.assertEqual(json.loads(g2a["content"])["accounts"][0]["email"], "user@outlook.com")
            self.assertEqual(_find_account_auth_file(record, config, "cpa"), cpa_path)

    def test_rejects_unknown_kind(self):
        with self.assertRaises(ValueError):
            _load_account_auth_json({}, {}, "other")

    def test_file_finder_does_not_parse_content_for_download(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid_json = root / "xai-user@example.com.json"
            invalid_json.write_text("not parsed by download path", encoding="utf-8")
            record = {"email": "user@example.com", "cpa_auth_path": str(invalid_json)}
            config = {"cpa_auth_dir": str(root)}

            self.assertEqual(_find_account_auth_file(record, config, "cpa"), invalid_json)
            with self.assertRaises(ValueError):
                _load_account_auth_json(record, config, "cpa")

    def test_stream_file_uses_incremental_chunks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_bytes(b"abcdefghij")
            self.assertEqual(list(_stream_file(path, chunk_size=4)), [b"abcd", b"efgh", b"ij"])

    def test_batch_archive_exports_available_files_and_reports_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            auth_file = root / "xai-user@example.com.json"
            auth_file.write_text(json.dumps({"email": "user@example.com"}), encoding="utf-8")
            records = [
                {"id": 7, "email": "user@example.com", "cpa_auth_path": str(auth_file)},
                {"id": 8, "email": "missing@example.com"},
            ]

            content, exported, skipped = build_account_auth_archive(
                records,
                {"cpa_auth_dir": str(root)},
                "cpa",
                _find_account_auth_file,
            )

            self.assertEqual((exported, skipped), (1, 1))
            with zipfile.ZipFile(BytesIO(content)) as archive:
                self.assertEqual(archive.namelist(), ["7-xai-user@example.com.json"])
                payload = json.loads(archive.read(archive.namelist()[0]))
                self.assertEqual(payload["email"], "user@example.com")


if __name__ == "__main__":
    unittest.main()
