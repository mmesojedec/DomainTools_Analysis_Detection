"""The copyable curl / CLI / Python on the IrisQL and CertsQL pages: valid shell and Python, answer piped to jq."""
import ast
import json
import shutil
import subprocess

import pytest

from core import certsql, irisql

CERTS = certsql.normalize('san_dns contains "login"\nAND\nissuer_organization in ["Let\'s Encrypt", "ZeroSSL"]')
IRIS = irisql.normalize('DOMAIN CONTAINS "it\'s"\nAND\nRISK_SCORE GREATER_THAN 70')
ALL = [*certsql.commands(CERTS, 500, certsql.sort_term("validity_not_before", "desc")).items(),
       *certsql.commands(CERTS, 100).items(), *irisql.commands(IRIS, 500, "risk_score").items(),
       ("curl, text", certsql.commands(CERTS, 500, certsql.sort_term("validity_not_before", "desc"), "Text")["curl"])]


@pytest.mark.parametrize("label,code", ALL)
def test_every_command_is_valid_shell_or_python(label, code):
    if label == "Python script":
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
    code = certsql.commands(CERTS, 500)["Python script"]
    names = {}
    exec(code.split("response =")[0], names)   # stop before the request
    assert names["body"] == certsql.payload(CERTS, 500)


def test_copy_fallback_is_installed_on_every_page():
    from views import common
    assert "execCommand(\"copy\")" in common._COPY_FALLBACK and "writeText" in common._COPY_FALLBACK
    source = open("app.py", encoding="utf-8").read()
    assert "install_copy_fallback()" in source


def test_text_curl_writes_the_query_as_lines_and_sends_the_same_body():
    sort = certsql.sort_term("validity_not_before", "desc")
    code = certsql.commands(CERTS, 500, sort, "Text")["curl"]
    assert f"\n{CERTS}\nEOF" in code and "\\n" not in code.split("<<'EOF'")[1]   # the query unescaped, as typed
    assert "--json @-" in code and code.splitlines()[2].endswith("| jq .")
    assert certsql.commands(CERTS, 500, sort)["curl"] == certsql.commands(CERTS, 500, sort, "JSON")["curl"]
    if shutil.which("bash") and shutil.which("jq"):   # stand-in curl echoes what jq built: the JSON form's body
        run = subprocess.run(["bash", "-c", "curl() { cat; }\n" + code], capture_output=True, text=True)
        assert run.returncode == 0, run.stderr
        assert json.loads(run.stdout) == certsql.payload(CERTS, 500, sort)
