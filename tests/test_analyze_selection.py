from views.analyze_selection import SCOPES, analyze_label, default_scope, scope_label, scope_targets

DOMAINS, IPS = ["finsors.com", "flowers-to-gophers.com"], ["34.118.224.1"]


def test_the_scope_decides_which_ticked_targets_the_run_takes():
    assert scope_targets("domains", DOMAINS, IPS) == (DOMAINS, [])
    assert scope_targets("ips", DOMAINS, IPS) == ([], IPS)
    assert scope_targets("both", DOMAINS, IPS) == (DOMAINS, IPS)
    assert set(SCOPES) == {"domains", "ips", "both"}


def test_labels_say_what_will_be_analyzed():
    assert [scope_label(s, DOMAINS, IPS) for s in SCOPES] == ["Domains (2)", "IPs (1)", "Domains & IPs (3)"]
    assert analyze_label(DOMAINS, []) == "Analyze 2 domains"
    assert analyze_label([], IPS) == "Analyze 1 IP"
    assert analyze_label(DOMAINS, IPS) == "Analyze 2 domains & 1 IP"
    assert analyze_label([], []) == "Analyze"


def test_ticked_ips_are_not_analyzed_unless_chosen():
    assert default_scope(DOMAINS, IPS) == "domains"   # the pre-selected IPs no longer slip into a domain run
    assert default_scope([], IPS) == "ips"
    assert default_scope([], []) == "domains"
