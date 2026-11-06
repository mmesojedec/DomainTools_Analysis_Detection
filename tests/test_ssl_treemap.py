import pandas as pd

from views.ssl_view import san_treemap_records


def _cert(domain, sha, sans):
    return {"Domain": domain, "Hash": sha, "Source": "Cert API", "Alt Names List": list(sans)}


def test_treemap_groups_extra_certificates_and_sans_but_keeps_box_sizes():
    certs = [_cert("big.com", f"{i:02x}" + "0" * 62, [f"h{i}-{j}.big.com" for j in range(20 if i == 0 else 2)]) for i in range(30)]
    certs.append(_cert("small.com", "f" * 64, ["small.com", "www.small.com"]))
    frame = pd.DataFrame(certs)
    rows, capped = san_treemap_records(frame, max_certs=5, max_sans=10)
    assert capped
    table = pd.DataFrame(rows)
    big = table[table["Target Domain"] == "big.com"]
    assert big["Count"].sum() == 20 + 29 * 2   # every SAN still counted
    assert big["Certificate"].nunique() == 6   # five certificates and one "+25 more certificates" box
    assert "+10 more SANs" in set(big["SAN Domain"]) and "+25 more certificates" in set(big["Certificate"])
    assert len(table) < 30   # a few dozen boxes instead of one per SAN

    rows, capped = san_treemap_records(frame[frame["Domain"] == "small.com"])
    assert not capped and sorted(row["SAN Domain"] for row in rows) == ["small.com", "www.small.com"]
