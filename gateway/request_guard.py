"""Runs before every call LiteLLM makes, for the two things no LiteLLM setting holds.

Fields: only the listed ones go on. Others can reach the upstream unpriced: extra_body can set the model or stream behind
LiteLLM's back and a client's additional_drop_params turns off any configured drop.

Budget: a request is refused unless the key can pay its worst case with what running requests may still cost. LiteLLM reserves
output only and admits a request over the remainder, and with its token counter off it reserves no input at all.
"""
import json
import os
import time
import uuid

import litellm
import yaml
from litellm.integrations.custom_logger import CustomLogger

ALLOWED = frozenset({
    "model", "messages", "system", "stream", "stream_options", "max_tokens", "max_completion_tokens", "temperature", "top_p",
    "top_k", "stop", "stop_sequences", "presence_penalty", "frequency_penalty", "seed", "tools", "tool_choice",
    "parallel_tool_calls", "response_format", "reasoning_effort", "thinking", "metadata", "user", "n", "logit_bias", "logprobs",
    "top_logprobs", "input",  # input: the other routes fail upstream, as they should, rather than in here
    "litellm_metadata",  # LiteLLM's own on /v1/messages, already in this body: without it the spend finds no key
})
LITELLM_OWN = frozenset({"litellm_call_id", "litellm_logging_obj", "proxy_server_request"})  # a client's value does not remove them
MESSAGES_CALL = "anthropic_messages"
NOT_SENT_UPSTREAM = ("metadata", "litellm_metadata", "user")
OUTPUT_FIELDS = ("max_completion_tokens", "max_tokens", "max_output_tokens")
DEFAULT_OUTPUT_TOKENS = 16384  # the egress's litellmDefaultOutput: what it lets a request naming no limit produce
HOLD_SECONDS = 20  # a finished request stays counted until its spend is sure to show: LiteLLM flushes spend about every 10 s
LONGEST_REQUEST_SECONDS = 720  # past the drain's 11-minute cut, for a request whose end nothing reported


def load_models(path):
    """The measured prices and limits, by the name clients request."""
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return {entry["model_name"]: {
        "input_usd": float(entry["litellm_params"]["input_cost_per_token"]),
        "output_usd": float(entry["litellm_params"]["output_cost_per_token"]),
        "max_input": int(entry["model_info"]["max_input_tokens"]),
        "max_output": int(entry["model_info"]["max_output_tokens"]),
    } for entry in config["model_list"]}


def worst_case_usd(model, body_bytes, requested):
    """Input at one token per byte, which no tokenizer exceeds, up to the model's context; output as the egress clamps it."""
    named = [value for value in requested if isinstance(value, int) and value >= 1]
    output = min(min(named) if named else DEFAULT_OUTPUT_TOKENS, model["max_output"])
    return min(body_bytes, model["max_input"]) * model["input_usd"] + output * model["output_usd"]


class Ledger:
    """What running requests may still cost, per key. One process serves the proxy, so memory is the whole count."""

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._keys = {}
        self._owners = {}

    def _running(self, key):
        now = self._clock()
        calls = self._keys.get(key, {})
        for call in [call for call, (_, expires) in calls.items() if expires <= now]:
            del calls[call]
            del self._owners[call]
        if not calls:
            self._keys.pop(key, None)
        return sum(amount for amount, _ in calls.values())

    def admit(self, key, call, amount, remaining):
        """Counts the request if the key can pay it on top of the others, and says whether it could."""
        if call in self._owners:  # a client can name the id, and reusing one would overwrite what is counted
            return False
        if amount > remaining - self._running(key):
            return False
        self._keys.setdefault(key, {})[call] = (amount, self._clock() + LONGEST_REQUEST_SECONDS)
        self._owners[call] = key
        return True

    def finish(self, call):
        key = self._owners.get(call)
        if key is not None:
            amount, _ = self._keys[key][call]
            self._keys[key][call] = (amount, self._clock() + HOLD_SECONDS)


class RequestGuard(CustomLogger):
    def __init__(self, models, ledger):
        super().__init__()
        self.models = models
        self.ledger = ledger

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        for field in set(data["proxy_server_request"]["body"]) - ALLOWED - LITELLM_OWN:
            data.pop(field, None)
        # LiteLLM keeps its own record of whose key this is in one of these and reads spend owners from the other too, so a
        # client's copy there could charge another key or none. Each route has its own; the other is only ever the client's.
        data.pop("metadata" if call_type == MESSAGES_CALL else "litellm_metadata", None)
        if user_api_key_dict.max_budget is not None:
            self._charge(user_api_key_dict, data)
        return data

    def _charge(self, auth, data):
        model = self.models.get(data.get("model"))
        spend = auth.spend or 0.0
        if model is None:
            raise litellm.BudgetExceededError(current_cost=spend, max_budget=auth.max_budget, message="no price for this model")
        sent = {field: value for field, value in data.items() if field in ALLOWED and field not in NOT_SENT_UPSTREAM}
        body_bytes = len(json.dumps(sent, ensure_ascii=False, default=str).encode())
        cost = worst_case_usd(model, body_bytes, [data.get(field) for field in OUTPUT_FIELDS])
        call = data.setdefault("litellm_call_id", str(uuid.uuid4()))
        if not self.ledger.admit(auth.token, call, cost, auth.max_budget - spend):
            raise litellm.BudgetExceededError(current_cost=spend, max_budget=auth.max_budget, message=(
                "This key cannot cover this request's worst case of %.4f USD on top of its running requests. "
                "Send less, name a smaller max_tokens, wait for running requests to end, or top up." % cost))

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        self.ledger.finish(kwargs.get("litellm_call_id"))

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        self.ledger.finish(kwargs.get("litellm_call_id"))


guard = RequestGuard(load_models(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")), Ledger())
