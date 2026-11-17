"""The OpenAI backend pointed at a local OpenAI-compatible server (Ollama, LM Studio, ...).

A stub server on 127.0.0.1 stands in for the model, so these run offline. They check that OPENAI_BASE_URL is
honoured without a real key, that a reasoning model's <think> block (here containing a made-up citation) never
reaches the citation enforcer, and that a model slower than BANKSHIELD_LLM_TIMEOUT degrades to the labelled
offline fallback instead of hanging.
"""
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from bankshield import config
from bankshield.rag import pipeline
from bankshield.rag.llm import OpenAILLM, strip_thinking
from bankshield.rag.pipeline import ask

pytest.importorskip("openai")

_ID = re.compile(r"\b([A-Z]{2,4}(?:-[A-Z]{2,4})?-\d+(?:\.\d+)?)\b")


class _Stub:
    """Answers chat completions by citing the first clause ID in the evidence, after an optional delay."""

    def __init__(self, delay: float = 0.0, think: bool = False):
        self.delay, self.think, self.requests = delay, think, []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers["content-length"])))
                stub.requests.append((self.path, self.headers.get("authorization"), req))
                time.sleep(stub.delay)
                user = req["messages"][-1]["content"]
                ids = _ID.findall(user)
                answer = f"The policy requirement is set out in [{ids[0]}]." if ids else "The evidence does not answer this."
                if stub.think:
                    answer = "<think>Maybe the rule is [ZZZ-9.9]? Check the evidence.</think>\n" + answer
                body = json.dumps({"id": "x", "object": "chat.completion", "created": 0, "model": req["model"],
                                   "choices": [{"index": 0, "finish_reason": "stop",
                                                "message": {"role": "assistant", "content": answer}}],
                                   "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}).encode()
                try:
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up (timeout test)

        self.server = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def close(self):
        self.server.shutdown()


@pytest.fixture()
def local_model(monkeypatch):
    stubs = []

    def make(**kw):
        s = _Stub(**kw)
        stubs.append(s)
        monkeypatch.setenv("OPENAI_BASE_URL", s.url)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setattr(config, "OPENAI_MODEL", "qwen2.5:7b")
        monkeypatch.setattr(pipeline, "_LLM", OpenAILLM())
        return s

    yield make
    for s in stubs:
        s.close()


def test_strip_thinking():
    assert strip_thinking("<think>a [X-1]</think>\nanswer [CSP-4.2]") == "answer [CSP-4.2]"
    assert strip_thinking("<think>cut off while still reasoning [X-1]") == ""
    assert strip_thinking("  plain [CSP-4.2] ") == "plain [CSP-4.2]"


def test_openai_backend_reaches_a_local_server_without_a_real_key(conn, local_model):
    stub = local_model()
    a = ask(conn, "How often must CMEK keys rotate?", user="asha.analyst")
    assert not a.refused and a.backend == "openai", (a.backend, a.notes)
    assert a.citations, a.answer
    path, auth, req = stub.requests[0]
    assert path == "/v1/chat/completions" and req["model"] == "qwen2.5:7b" and req["temperature"] == 0
    assert auth == "Bearer local"  # placeholder key: local servers ignore it, the SDK requires one


def test_a_reasoning_block_never_reaches_the_citation_enforcer(conn, local_model):
    local_model(think=True)
    a = ask(conn, "How often must CMEK keys rotate?", user="asha.analyst")
    assert a.backend == "openai" and not a.refused
    assert "ZZZ-9.9" not in a.answer and "ZZZ-9.9" not in a.citations and "<think>" not in a.answer


def test_a_model_slower_than_the_timeout_falls_back_and_is_labelled(conn, local_model, monkeypatch):
    monkeypatch.setattr(config, "LLM_TIMEOUT_S", 0.3)
    local_model(delay=3.0)
    monkeypatch.setattr(pipeline, "_LLM", OpenAILLM())  # rebuild the client with the short timeout
    t0 = time.perf_counter()
    a = ask(conn, "How often must CMEK keys rotate?", user="asha.analyst")
    assert a.backend == "extractive(fallback)" and "unavailable" in a.answer
    assert time.perf_counter() - t0 < 2.9 * 3  # bounded by the timeout and the SDK's retries, not left hanging
