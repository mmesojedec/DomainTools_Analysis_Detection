import integrations.collector as collector
import integrations.progress as progress_module
from core.use_cases import query_plan
from integrations.http import FetchResult, StatusLog
from integrations.progress import DONE, RUNNING, SKIPPED, WAITING, CollectionProgress, tracking
from views.collection_progress import (
    cache_table,
    cache_text,
    checklist_lines,
    clock,
    completed_share,
    ordered,
    summary,
    up_next,
)

PLAN = query_plan({"opt_txt": True, "opt_caa": True, "opt_cname": False, "opt_pivot": False})


def rows(progress):
    return {row.key: row for row in progress.snapshot()}


def test_every_plan_row_has_a_key_and_starts_waiting():
    progress = CollectionProgress(PLAN)
    assert all(row["Key"] for row in PLAN)
    assert {row.state for row in progress.snapshot()} == {WAITING}
    assert set(rows(progress)) == {"iris", "history", "certs", "pdns", "TXT", "CAA", "vpndb", "ct"}


def test_supplements_count_only_the_capped_domains_and_skip_when_none_were_capped(monkeypatch):
    def fake_fetch(target, limit=5000, rrtype="ANY", include_wildcard=True):
        return FetchResult("DNSDB Scout", target, data=[], truncated=rrtype == "ANY" and target == "big.com",
                           record_count=3, note="From cache (1 h old)" if target == "small.com" else None)

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake_fetch)
    drawn = []
    progress = CollectionProgress(PLAN, render=lambda p: drawn.append(1))
    with tracking(progress):
        collector.collect_pdns(["big.com", "small.com"], "DNSDB Scout", 10, StatusLog(), txt_records=5, caa_lookup=True)
    found = rows(progress)
    assert (found["pdns"].state, found["pdns"].done, found["pdns"].total, found["pdns"].cached) == (DONE, 2, 2, 1)
    assert (found["TXT"].state, found["TXT"].done, found["TXT"].total) == (DONE, 1, 1)
    assert "not needed for 1" in found["TXT"].note
    assert drawn

    monkeypatch.setattr(collector, "fetch_dnsdb_history",
                        lambda t, limit=5000, rrtype="ANY", include_wildcard=True: FetchResult("DNSDB Scout", t, data=[]))
    progress = CollectionProgress(PLAN)
    with tracking(progress):
        collector.collect_pdns(["small.com"], "DNSDB Scout", 10, StatusLog(), txt_records=5, caa_lookup=True)
    assert rows(progress)["CAA"].state == SKIPPED and rows(progress)["CAA"].note.startswith("Not needed")


def test_failed_lookups_that_succeed_on_retry_are_not_counted_as_failed():
    attempts = {}

    def lookup(job):
        attempts[job] = attempts.get(job, 0) + 1
        return FetchResult("Cert", job, error="HTTP 503" if attempts[job] == 1 and job == "b" else None)

    progress = CollectionProgress(PLAN)
    with tracking(progress):
        progress.start("ct", 2)
        collector.run_with_retry(["a", "b"], lookup, pause=0, key="ct")
    assert (rows(progress)["ct"].done, rows(progress)["ct"].failed) == (2, 0)


def test_close_marks_rows_never_reached_as_skipped_and_the_summary_counts_them():
    progress = CollectionProgress(PLAN)
    progress.start("history", 1)
    progress.advance("history", FetchResult("Domain History", "a.com", record_count=4))
    assert rows(progress)["history"].state == RUNNING
    assert 0 < completed_share(progress.snapshot()) < 1
    progress.close()
    snapshot = progress.snapshot()
    assert rows(progress)["history"].state == DONE and rows(progress)["iris"].state == SKIPPED
    assert completed_share(snapshot) == 1.0
    assert summary(snapshot).startswith("1 lookup type(s) run (1 lookups)")
    assert any("1/1 lookup ·" in line and "4 records" in line for line in checklist_lines(snapshot))


def test_checklist_lists_finished_rows_first_in_finishing_order_and_leaves_waiting_rows_to_up_next():
    progress = CollectionProgress(PLAN)
    progress.start("history", 1)
    progress.start("certs", 2)
    progress.finish("certs")
    progress.skip("TXT", "Not needed")
    progress.advance("history", FetchResult("Domain History", "a.com"))
    snapshot = progress.snapshot()
    assert [row.key for row in ordered(snapshot)][:3] == ["certs", "TXT", "history"]
    lines = checklist_lines(snapshot)
    assert len(lines) == 3 and lines[0].startswith(":green-badge[100%]") and lines[1].startswith(":gray-badge[skipped]")
    assert lines[2].startswith(":blue-badge[100%] **Domain History**")   # still running: 1/1 lookup, not finished
    assert up_next(snapshot).startswith("Up next: **Iris Investigate**")
    assert clock(5.4) == "5 s" and clock(65) == "1:05"


def test_lookups_outside_a_tracked_run_are_not_counted():
    assert collector._parallel([1, 2], lambda x: x * 2, key="pdns") == [2, 4]


def test_cached_results_say_how_old_they_are_and_when_they_expire():
    progress = CollectionProgress(PLAN)
    progress.start("history", 2)
    for target, at in (("a.com", 1_000), ("b.com", 4_600)):
        progress.advance("history", FetchResult("Domain History", target, note="From cache (1 h old)", cached_at=at))
    row = rows(progress)["history"]
    assert cache_text(row, lifetime=86_400, now=8_200) == ":violet[2 from cache]: up to 2 h old, first expires in 22 h"
    row.cached, row.cache_hits = 1, row.cache_hits[1:]
    assert cache_text(row, lifetime=86_400, now=8_200) == ":violet[from cache]: fetched 1 h ago, expires in 23 h"
    table = cache_table(progress.snapshot(), lifetime=3_600, now=8_000)
    assert table[["Target", "Expires"]].values.tolist() == [["a.com", "expired"], ["b.com", "in 3 min"]]


def test_a_row_started_again_later_counts_only_its_running_time(monkeypatch):
    clock_now = [100.0]
    monkeypatch.setattr(progress_module.time, "monotonic", lambda: clock_now[0])
    progress = CollectionProgress(PLAN)
    progress.start("certs", 1)
    clock_now[0] = 102.0
    progress.finish("certs")
    clock_now[0] = 150.0   # other lookups run meanwhile
    progress.start("certs", 2)
    assert rows(progress)["certs"].took(now=153.0) == 5.0
    clock_now[0] = 156.0
    progress.finish("certs")
    assert rows(progress)["certs"].took() == 8.0


def test_iris_pdns_redraws_while_a_lookup_runs_and_relays_the_login_prompt_to_this_thread(monkeypatch):
    import threading
    import time

    drawing_thread, calls = threading.current_thread(), []

    def slow_fetch(targets, on_auth_required=None, on_auth_done=None, extra_rrtypes=(), if_capped_rrtypes=(),
                   on_result=None):
        assert threading.current_thread() is not drawing_thread   # the lookups run in a worker thread
        on_auth_required(targets[0])
        time.sleep(1.3)   # longer than CLOCK_SECONDS, so the clock must be redrawn while it runs
        on_auth_done()
        results = {t: FetchResult("Iris pDNS", t, data=[], record_count=0) for t in targets}
        for target, result in results.items():
            on_result(target, result)
        return results

    monkeypatch.setattr(collector, "fetch_iris_pdns_many", slow_fetch)
    drawn = []
    progress = CollectionProgress(PLAN, render=lambda p: drawn.append(
        next(row.state for row in p.snapshot() if row.key == "pdns")))
    with tracking(progress):
        collector.collect_pdns(["slow.com"], "Iris pDNS", 10, StatusLog(),
                               on_auth_required=lambda t: calls.append(("required", t, threading.current_thread())),
                               on_auth_done=lambda: calls.append(("done", None, threading.current_thread())))
    assert drawn.count(RUNNING) >= 2   # redrawn during the lookup, not only before and after it
    assert [(name, target) for name, target, _ in calls] == [("required", "slow.com"), ("done", None)]
    assert all(thread is drawing_thread for _, _, thread in calls)   # the UI callbacks ran on the drawing thread
    assert rows(progress)["pdns"].done == 1
