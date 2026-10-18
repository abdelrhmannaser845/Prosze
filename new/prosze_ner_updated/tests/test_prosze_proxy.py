import io
import json
import sys
import tempfile
import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import HTTPConnection
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import prosze_proxy


class UpstreamHandler(BaseHTTPRequestHandler):
    last_body = None
    last_path = None

    def do_POST(self):
        type(self).last_path = self.path
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        type(self).last_body = body
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        response = json.dumps({"received": body.decode(), "reply": "[[EMAIL_1]]"}).encode()
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


class ProxyBoundaryTests(unittest.TestCase):
    @staticmethod
    def vault(path):
        vault = prosze_proxy.Vault(path)
        vault._ner_attempted = True
        return vault

    def test_stream_restorer_restores_complete_placeholder_and_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = self.vault(str(Path(directory) / "map"))
            vault.save("Ada Lovelace", "PERSON")
            restorer = prosze_proxy.StreamRestorer(vault)
            result = restorer.feed_bytes(
                b"id: 7\nevent: message\ndata: {\"choices\": [{\"index\": 0, "
                b"\"delta\": {\"content\": \"[[PERSON_1]]\"}}]}\n\n"
            ) + restorer.finish()
        self.assertIn(b"id: 7\n", result)
        self.assertIn(b"Ada Lovelace", result)

    def test_stream_restorer_flushes_held_partial_placeholder(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = self.vault(str(Path(directory) / "map"))
            vault.save("Ada Lovelace", "PERSON")
            restorer = prosze_proxy.StreamRestorer(vault)
            result = restorer.feed_bytes(
                b"data: {\"choices\": [{\"index\": 0, "
                b"\"delta\": {\"content\": \"hello [[PERSON_\"}}]}\n\n"
            ) + restorer.finish()
        self.assertIn(b"hello", result)
        self.assertIn(b"[[PERSON_", result)

    def test_fail_closes_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            handler_type = prosze_proxy.make_handler(
                self.vault(str(Path(directory) / "map")), "http://localhost", False
            )
            handler = object.__new__(handler_type)
            sent_headers = {}
            handler.send_response = lambda code: setattr(handler, "status", code)
            handler.send_header = lambda key, value: sent_headers.setdefault(key, value)
            handler.end_headers = lambda: None
            handler.wfile = io.BytesIO()
            handler.close_connection = False
            handler._fail(400, "malformed request")
        self.assertEqual(handler.status, 400)
        self.assertEqual(sent_headers["Connection"], "close")
        self.assertTrue(handler.close_connection)

    def test_read_body_rejects_ambiguous_framing(self):
        with tempfile.TemporaryDirectory() as directory:
            handler_type = prosze_proxy.make_handler(
                self.vault(str(Path(directory) / "map")), "http://localhost", False
            )
            handler = object.__new__(handler_type)
            handler.headers = Message()
            handler.headers["Transfer-Encoding"] = "chunked"
            handler.headers["Content-Length"] = "4"
            handler.rfile = io.BytesIO(b"4\r\ntest\r\n0\r\n\r\n")
            with self.assertRaisesRegex(ValueError, "both"):
                handler._read_body()

    def test_proxy_redacts_request_and_restores_json_response(self):
        with tempfile.TemporaryDirectory() as directory:
            vault = self.vault(str(Path(directory) / "map"))
            secret = "ada@example.com"
            placeholder, _ = vault.redact(secret)
            upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
            proxy = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                prosze_proxy.make_handler(
                    vault, f"http://127.0.0.1:{upstream.server_address[1]}/api/", False
                ),
            )
            upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            upstream_thread.start()
            proxy_thread.start()
            try:
                connection = HTTPConnection("127.0.0.1", proxy.server_address[1])
                payload = json.dumps({"message": secret}).encode()
                connection.request("POST", "/v1/messages?stream=false", payload,
                                   {"Content-Type": "application/json"})
                response = connection.getresponse()
                result = json.loads(response.read())
                connection.close()
            finally:
                proxy.shutdown()
                upstream.shutdown()
                proxy.server_close()
                upstream.server_close()
            self.assertEqual(UpstreamHandler.last_body.decode(),
                             json.dumps({"message": placeholder}, ensure_ascii=False))
            self.assertEqual(UpstreamHandler.last_path, "/api/v1/messages?stream=false")
            self.assertEqual(result["reply"], secret)


if __name__ == "__main__":
    unittest.main()
