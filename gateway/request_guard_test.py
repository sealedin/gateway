"""Tests for the request guard's arithmetic (CI: python3 -I -B -W error -m unittest discover -s gateway -p '*_test.py')."""
import asyncio
import importlib.util
import os
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))


class BudgetExceededError(Exception):
    def __init__(self, current_cost, max_budget, message):
        super().__init__(message)


def load_guard():
    """Loads the module with stand-ins for what only the gateway image has, and one model table in place of the YAML."""
    logger = types.ModuleType("litellm.integrations.custom_logger")
    logger.CustomLogger = type("CustomLogger", (), {})
    fake_yaml = types.ModuleType("yaml")
    fake_yaml.safe_load = lambda _: {"model_list": []}
    fake = {"litellm": types.SimpleNamespace(BudgetExceededError=BudgetExceededError), "litellm.integrations": types.ModuleType("x"),
            "litellm.integrations.custom_logger": logger, "yaml": fake_yaml}
    spec = importlib.util.spec_from_file_location("request_guard", os.path.join(HERE, "request_guard.py"))
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, fake):
        spec.loader.exec_module(module)
    return module


rg = load_guard()
# gateway/config.yaml's Kimi-K3: TestGuardArithmeticUsesTheMeasuredConfig in internal/gateway holds these equal to it.
KIMI = {"input_usd": 1.9425e-6, "output_usd": 9.975e-6, "max_input": 1048576, "max_output": 65535}
FULL_CONTEXT = 1048576


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


def auth(spend, budget=25.0):
    return types.SimpleNamespace(token="hash", spend=spend, max_budget=budget)


def request(call, content_bytes=FULL_CONTEXT, max_tokens=1):
    body = {"model": "kimi", "messages": [{"role": "user", "content": "x" * content_bytes}], "max_tokens": max_tokens}
    return {**body, "litellm_call_id": call, "proxy_server_request": {"body": dict(body)}}


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.guard = rg.RequestGuard({"kimi": KIMI}, rg.Ledger(self.clock))

    def admit(self, data, key):
        try:
            asyncio.run(self.guard.async_pre_call_hook(key, None, data, "acompletion"))
            return True
        except BudgetExceededError:
            return False

    def test_the_twenty_usd_case_is_closed(self):
        """Ten full-context requests naming one output token, on a key with 1 USD left: none of the 20.40 USD gets out."""
        admitted = [self.admit(request(str(i)), auth(spend=24.0)) for i in range(10)]
        self.assertEqual(admitted, [False] * 10)

    def test_running_requests_count(self):
        """With 5 USD left each worst case of 2.04 USD fits twice; the third is refused while the others run."""
        admitted = [self.admit(request(str(i)), auth(spend=20.0)) for i in range(10)]
        self.assertEqual(admitted, [True, True] + [False] * 8)

    def test_what_gets_through_cannot_exceed_the_budget(self):
        left = 5.0
        admitted = sum(self.admit(request(str(i)), auth(spend=25.0 - left)) for i in range(10))
        self.assertLessEqual(admitted * rg.worst_case_usd(KIMI, FULL_CONTEXT, [1]), left)

    def test_a_finished_request_frees_its_count_after_the_hold(self):
        self.assertTrue(self.admit(request("a"), auth(spend=22.5)))
        self.assertFalse(self.admit(request("b"), auth(spend=22.5)))
        asyncio.run(self.guard.async_log_success_event({"litellm_call_id": "a"}, None, 0, 0))
        self.clock.now += rg.HOLD_SECONDS - 1
        self.assertFalse(self.admit(request("c"), auth(spend=22.5)), "still counted until its spend shows")
        self.clock.now += 2
        self.assertTrue(self.admit(request("d"), auth(spend=22.5)))

    def test_a_failed_request_frees_its_count(self):
        self.assertTrue(self.admit(request("a"), auth(spend=22.5)))
        asyncio.run(self.guard.async_log_failure_event({"litellm_call_id": "a"}, None, 0, 0))
        self.clock.now += rg.HOLD_SECONDS + 1
        self.assertTrue(self.admit(request("b"), auth(spend=22.5)))

    def test_a_lost_end_cannot_hold_a_key_forever(self):
        self.assertTrue(self.admit(request("a"), auth(spend=22.5)))
        self.clock.now += rg.LONGEST_REQUEST_SECONDS + 1
        self.assertTrue(self.admit(request("b"), auth(spend=22.5)))

    def test_a_reused_call_id_cannot_overwrite_what_is_counted(self):
        self.assertTrue(self.admit(request("same"), auth(spend=22.5)))
        tiny = request("same", content_bytes=1)
        self.assertFalse(self.admit(tiny, auth(spend=22.5)))
        self.assertFalse(self.admit(request("other"), auth(spend=22.5)), "the first still counts")

    def test_a_client_cannot_remove_litellms_own_fields(self):
        data = request("a", content_bytes=1)
        data["proxy_server_request"]["body"]["litellm_call_id"] = "mine"
        self.assertTrue(self.admit(data, auth(spend=0.0)))
        self.assertEqual(data["litellm_call_id"], "a")

    def test_a_clients_copy_of_litellms_metadata_is_dropped_on_each_route(self):
        spoof = {"user_api_key": "someone else"}
        for call_type, kept, dropped in (("acompletion", "metadata", "litellm_metadata"), ("anthropic_messages", "litellm_metadata", "metadata")):
            data = request("a" + call_type, content_bytes=1)
            data[kept], data[dropped] = {"own": 1}, spoof
            asyncio.run(self.guard.async_pre_call_hook(auth(spend=0.0), None, data, call_type))
            self.assertEqual(data[kept], {"own": 1})
            self.assertNotIn(dropped, data)

    def test_output_counts_as_the_egress_clamps_it(self):
        for requested, want in (([], rg.DEFAULT_OUTPUT_TOKENS), ([10**9], 65535), ([5], 5), ([5, 10**9], 5), ([None, 7], 7)):
            self.assertAlmostEqual(rg.worst_case_usd(KIMI, 0, requested), want * KIMI["output_usd"])

    def test_input_counts_bytes_up_to_the_context(self):
        self.assertAlmostEqual(rg.worst_case_usd(KIMI, 1000, [1]) - KIMI["output_usd"], 1000 * KIMI["input_usd"])
        self.assertEqual(rg.worst_case_usd(KIMI, 10**9, [1]), rg.worst_case_usd(KIMI, FULL_CONTEXT, [1]))

    def test_multibyte_text_counts_its_bytes(self):
        data = request("a", content_bytes=0)
        data["messages"][0]["content"] = "\U0001F600" * 100000  # 4 bytes, up to 4 tokens
        self.assertFalse(self.admit(data, auth(spend=24.5, budget=25.0 - 0.3)))

    def test_an_unpriced_model_is_refused_for_a_key_with_a_budget(self):
        data = request("a")
        data["model"] = "other"
        self.assertFalse(self.admit(data, auth(spend=0.0)))

    def test_no_budget_means_no_charge(self):
        self.assertTrue(self.admit(request("a"), auth(spend=0.0, budget=None)))

    def test_unlisted_fields_never_go_on(self):
        data = request("a", content_bytes=1)
        extra = {"extra_body": {"model": "other"}, "additional_drop_params": [], "foo": 1}
        data.update(extra)
        data["proxy_server_request"]["body"].update(extra)
        self.assertTrue(self.admit(data, auth(spend=0.0)))
        self.assertFalse(set(extra) & set(data))
        self.assertEqual(data["max_tokens"], 1)

    def test_the_refusal_names_no_content(self):
        data = request("a", content_bytes=10)
        data["messages"][0]["content"] = "secretprompt" * 100000
        with self.assertRaises(BudgetExceededError) as caught:
            asyncio.run(self.guard.async_pre_call_hook(auth(spend=25.0), None, data, "acompletion"))
        self.assertNotIn("secretprompt", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
