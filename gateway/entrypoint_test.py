"""Tests for the gateway entrypoint wrapper (CI: python3 -I -B -W error -m unittest discover -s gateway)."""

import importlib.util
import os
import shutil
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("entrypoint", os.path.join(HERE, "entrypoint.py"))
entrypoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entrypoint)

KEY = "sk-" + "ab" * 32


class EntrypointTest(unittest.TestCase):
    def setUp(self):
        self.key_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.key_dir)
        self.key_file = os.path.join(self.key_dir, "litellm-master-key")

    def write_key(self, text):
        with open(self.key_file, "w", encoding="ascii") as f:
            f.write(text)

    def test_reads_published_key(self):
        self.write_key(KEY + "\n")
        self.assertEqual(KEY, entrypoint.read_master_key(self.key_file))

    def test_folds_hex_case(self):
        self.write_key("sk-" + "AB" * 32)
        self.assertEqual(KEY, entrypoint.read_master_key(self.key_file))

    def test_only_a_missing_volume_is_dev_mode(self):
        self.assertTrue(entrypoint.key_volume_mounted(self.key_dir))
        self.assertFalse(entrypoint.key_volume_mounted(os.path.join(self.key_dir, "absent")))
        self.write_key(KEY)
        with self.assertRaises(NotADirectoryError):
            entrypoint.key_volume_mounted(os.path.join(self.key_file, "below-a-file"))

    def test_waits_for_the_identity_to_publish(self):
        timer = threading.Timer(0.2, self.write_key, [KEY])
        timer.start()
        self.addCleanup(timer.cancel)
        self.assertEqual(KEY, entrypoint.read_master_key(self.key_file, wait_seconds=5))

    def test_gives_up_after_the_wait(self):
        sleeps = []
        with self.assertRaises(RuntimeError):
            entrypoint.read_master_key(self.key_file, wait_seconds=0, sleep=sleeps.append)
        self.assertEqual([], sleeps)

    def test_rejects_oversized_file(self):
        self.write_key(KEY + " " * 200)
        with self.assertRaisesRegex(RuntimeError, "larger than"):
            entrypoint.read_master_key(self.key_file)

    def test_rejects_malformed_key(self):
        for text in ["", "sk-zz", KEY[:-1], KEY + "0", "xx-" + "ab" * 32, "sk-" + "zz" * 32]:
            with self.subTest(text=text):
                self.write_key(text)
                with self.assertRaises(RuntimeError):
                    entrypoint.read_master_key(self.key_file)

    def test_main_exports_key_from_volume_and_execs_stock_entrypoint(self):
        self.write_key(KEY)
        env, calls = {"LITELLM_MASTER_KEY": "sk-ignored"}, []
        entrypoint.main(["--config", "/config.yaml"], env, self.key_dir, self.key_file, lambda path, argv: calls.append((path, argv)))
        self.assertEqual(KEY, env["LITELLM_MASTER_KEY"], "the volume wins over the environment")
        self.assertEqual([(entrypoint.STOCK_ENTRYPOINT, [entrypoint.STOCK_ENTRYPOINT, "--config", "/config.yaml"])], calls)

    def test_main_without_volume_requires_env_key(self):
        absent = os.path.join(self.key_dir, "absent")
        calls = []
        with self.assertRaises(SystemExit):
            entrypoint.main([], {}, absent, absent + "/k", lambda *a: calls.append(a))
        self.assertEqual([], calls)
        env = {"LITELLM_MASTER_KEY": "sk-dev"}
        entrypoint.main(["--port", "4000"], env, absent, absent + "/k", lambda *a: calls.append(a))
        self.assertEqual("sk-dev", env["LITELLM_MASTER_KEY"])
        self.assertEqual(1, len(calls))


if __name__ == "__main__":
    unittest.main()
