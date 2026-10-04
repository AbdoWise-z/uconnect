"""Readiness must not use the dashboard's stale-on-error fallback."""
import unittest
from unittest.mock import patch

import app
from observer import Observer, ObserverError


class HealthTests(unittest.TestCase):
    def test_issue61_outage_after_cached_success(self):
        observer = Observer("example:4433", ttl=0)
        with patch.object(app, "observer", observer), patch.object(observer, "_run") as run:
            run.return_value = {"ok": True, "topics": [], "stats": {}}
            client = app.app.test_client()
            self.assertEqual(client.get("/healthz").status_code, 200)
            run.side_effect = ObserverError("server offline")
            for _ in range(2):
                response = client.get("/healthz")
                self.assertEqual(response.status_code, 503)
                self.assertFalse(response.json["ok"])
                self.assertIn("server offline", response.json["error"])
            self.assertTrue(observer.overview(members=False)[1])
            run.side_effect = None
            self.assertEqual(client.get("/healthz").status_code, 200)


if __name__ == "__main__":
    unittest.main()
