import time
import unittest
from unittest import mock

from backend.registration import engine
from backend.web.relogin_jobs import ReloginJobCoordinator


class _Store:
    def __init__(self, records):
        self.records = records

    def get_results_by_ids(self, ids):
        by_id = {record["id"]: record for record in self.records}
        return [by_id[account_id] for account_id in ids if account_id in by_id]


class ReloginJobCoordinatorTests(unittest.TestCase):
    def test_batch_preserves_order_and_counts_every_requested_account(self):
        store = _Store(
            [
                {"id": 1, "email": "one@example.com", "password": "secret"},
                {"id": 2, "email": "two@example.com", "password": ""},
                {"id": 3, "email": "three@example.com", "password": "secret"},
                {"id": 4, "email": "four@example.com", "password": "secret"},
            ]
        )
        coordinator = ReloginJobCoordinator()
        processed = []

        def run_record(record, _store):
            processed.append(record["id"])
            if record["id"] == 3:
                raise RuntimeError("fixture failure")
            return ""

        with (
            mock.patch.object(engine, "get_registration_repository", return_value=store),
            mock.patch.object(coordinator, "_run_record", side_effect=run_record),
        ):
            coordinator.start_many([4, 1, 2, 3, 99, 1])
            deadline = time.time() + 2
            while coordinator.status()["running"] and time.time() < deadline:
                time.sleep(0.01)

        status = coordinator.status()
        self.assertFalse(status["running"])
        self.assertEqual(processed, [4, 1, 3])
        self.assertEqual(status["total_count"], 5)
        self.assertEqual(status["completed_count"], 5)
        self.assertEqual(status["success_count"], 2)
        self.assertEqual(status["failed_count"], 3)
        self.assertEqual(status["error"], "3 个账号重新登录失败")

    def test_single_missing_account_keeps_not_found_contract(self):
        coordinator = ReloginJobCoordinator()
        with mock.patch.object(
            engine,
            "get_registration_repository",
            return_value=_Store([]),
        ):
            with self.assertRaisesRegex(LookupError, "记录不存在"):
                coordinator.start(7)

    def test_thread_start_failure_releases_running_state(self):
        coordinator = ReloginJobCoordinator()
        store = _Store([{"id": 1, "email": "one@example.com", "password": "secret"}])
        with (
            mock.patch.object(engine, "get_registration_repository", return_value=store),
            mock.patch("backend.web.relogin_jobs.threading.Thread.start", side_effect=RuntimeError("start failed")),
        ):
            with self.assertRaisesRegex(RuntimeError, "start failed"):
                coordinator.start(1)
        self.assertFalse(coordinator.status()["running"])


if __name__ == "__main__":
    unittest.main()
