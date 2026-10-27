import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from header_analyzer import analyse
from header_analyzer.cli import main
from header_analyzer.scanner import grade, normalise_url


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "Apache/2.4.41")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_normalise_url():
    assert normalise_url("example.com") == "https://example.com"
    assert normalise_url("http://example.com") == "http://example.com"


@pytest.mark.parametrize("score,letter", [(100, "A"), (85, "B"), (70, "C"), (55, "D"), (10, "F")])
def test_grade(score, letter):
    assert grade(score) == letter


def test_analyse_local_server(server):
    result = analyse(server)
    by_header = {f["header"]: f for f in result["findings"]}
    assert result["status_code"] == 200
    assert by_header["X-Content-Type-Options"]["status"] == "PASS"
    assert by_header["Content-Security-Policy"]["status"] == "MISSING"
    assert "Server" in by_header                      # version leak
    assert any(h.startswith("Set-Cookie") for h in by_header)
    assert 0 <= result["score"] < 100


def test_cli_writes_reports_and_fail_on(server, tmp_path, capsys):
    j, c = tmp_path / "r.json", tmp_path / "r.csv"
    code = main([server, "--json", str(j), "--csv", str(c), "--fail-on", "high", "--no-color"])
    assert code == 1
    data = json.loads(j.read_text())
    assert data["findings"] and "remediation" in data["findings"][0]
    assert c.read_text().splitlines()[0].startswith("url,score,grade")
    assert "Security Header Report" in capsys.readouterr().out


def test_cli_unreachable_returns_error(capsys):
    assert main(["http://127.0.0.1:1", "--timeout", "1"]) == 2
def test_cookie_values_are_redacted(server):
    result = analyse(server)
    cookie = next(f for f in result["findings"] if f["header"].startswith("Set-Cookie"))
    assert "sid=<redacted>" in cookie["value"]
    assert "sid=1" not in cookie["value"]
