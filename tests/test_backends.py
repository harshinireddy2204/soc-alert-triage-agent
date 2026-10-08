import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from triage.llm import BackendError, OllamaBackend, OpenAICompatibleBackend


class Handler(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Handler.received.append((self.path, body, self.headers.get("Authorization")))
        if self.path == "/api/chat":
            payload = {"message": {"content": '{"action": "final"}'}, "prompt_eval_count": 12, "eval_count": 3}
        elif self.path == "/v1/chat/completions":
            payload = {"choices": [{"message": {"content": '{"ok": true}'}}], "usage": {"prompt_tokens": 7, "completion_tokens": 2}}
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"bad request")
            return
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    Handler.received.clear()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


MESSAGES = [{"role": "user", "content": "hi"}]


def test_ollama_request_shape(server):
    reply = OllamaBackend("qwen2.5:7b", host=server, context_tokens=4096).chat(MESSAGES)
    assert (reply.text, reply.input_tokens, reply.output_tokens) == ('{"action": "final"}', 12, 3)
    path, body, _ = Handler.received[0]
    assert path == "/api/chat" and body["format"] == "json" and body["stream"] is False
    assert body["options"] == {"temperature": 0, "seed": 7, "num_ctx": 4096}


def test_openai_compatible_request_shape(server, monkeypatch):
    monkeypatch.setenv("MY_KEY", "secret")
    reply = OpenAICompatibleBackend("some-model", base_url=server + "/v1", api_key_env="MY_KEY").chat(MESSAGES)
    assert (reply.text, reply.input_tokens, reply.output_tokens) == ('{"ok": true}', 7, 2)
    path, body, auth = Handler.received[0]
    assert auth == "Bearer secret" and body["response_format"] == {"type": "json_object"} and body["temperature"] == 0


def test_errors_are_reported_clearly(server):
    with pytest.raises(BackendError, match="HTTP 400"):
        OpenAICompatibleBackend("m", base_url=server + "/nope").chat(MESSAGES)
    with pytest.raises(BackendError, match="cannot reach"):
        OllamaBackend("m", host="http://127.0.0.1:9", timeout=1).chat(MESSAGES)
