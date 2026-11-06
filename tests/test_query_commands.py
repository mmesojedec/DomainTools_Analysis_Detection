"""The copyable curl / CLI / Python on the IrisQL and CertsQL pages: valid shell and Python, answer piped to jq."""
import ast
import shutil
import subprocess

import pytest

from core import certsql, irisql

CERTS = certsql.normalize('san_dns contains "login"\nAND\nissuer_organization in ["Let\'s Encrypt", "ZeroSSL"]')
IRIS = irisql.normalize('DOMAIN CONTAINS "it\'s"\nAND\nRISK_SCORE GREATER_THAN 70')
ALL = [*certsql.commands(CERTS, 500, certsql.sort_term("validity_not_before", "desc")).items(),
       *certsql.commands(CERTS, 100).items(), *irisql.commands(IRIS, 500, "risk_score").items()]


@pytest.mark.parametrize("label,code", ALL)
def test_every_command_is_valid_shell_or_python(label, code):
    if label.startswith("Python"):
        ast.parse(code)
        assert "print(json.dumps(" in code and "USERNAME, KEY" not in code   # readable output, keys from env
    elif shutil.which("bash"):
        assert subprocess.run(["bash", "-n", "-c", code], capture_output=True).returncode == 0, code


def test_curl_pipes_the_answer_to_jq_and_still_sends_the_body():
    for code in (certsql.commands(CERTS, 500)["curl"], irisql.commands(IRIS, 500)["curl"]):
        first_line_of_body = code.splitlines()[2]
        assert first_line_of_body.endswith("<<'EOF' | jq .") and code.endswith("\nEOF")   # EOF alone on the last line
    if shutil.which("bash") and shutil.which("jq"):   # stand-in curl echoes the body: it reaches jq as valid JSON
        run = subprocess.run(["bash", "-c", "curl() { cat; }\n" + certsql.commands(CERTS, 500)["curl"]],
                             capture_output=True, text=True)
        assert run.returncode == 0 and '"limit": 500' in run.stdout


def test_python_body_is_the_query_sent():
    code = certsql.commands(CERTS, 500)["Python (requests)"]
    names = {}
    exec(code.split("response =")[0], names)   # stop before the request
    assert names["body"] == certsql.payload(CERTS, 500)


def test_copy_fallback_is_installed_on_every_page():
    from views import common
    assert "execCommand(\"copy\")" in common._COPY_FALLBACK and "writeText" in common._COPY_FALLBACK
    source = open("app.py", encoding="utf-8").read()
    assert "install_copy_fallback()" in source
