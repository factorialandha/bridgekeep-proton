"""The portal's settings form and the analyzer's settings.yaml reader must agree
on every key and range, or a saved value is ignored (or a key can't be set)."""
import ast
from pathlib import Path

from portal.portal_config import SETTINGS

ANALYZER = Path(__file__).resolve().parents[2] / "analyzer" / "src" / "analyzer" / "settings.py"


def _analyzer_keys() -> dict:
    tree = ast.parse(ANALYZER.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "KEYS":
            out = {}
            for k, v in zip(node.value.keys, node.value.values):
                _field, typ, lo, hi = v.elts
                out[ast.literal_eval(k)] = (typ.id, ast.literal_eval(lo), ast.literal_eval(hi))
            return out
    raise AssertionError("KEYS not found in analyzer settings.py")


def test_portal_and_analyzer_agree_on_settings_keys_and_ranges():
    analyzer = _analyzer_keys()
    assert set(SETTINGS) == set(analyzer)
    for key, (typ, lo, hi, _default) in SETTINGS.items():
        a_typ, a_lo, a_hi = analyzer[key]
        assert typ.__name__ == a_typ, key
        if lo is not None:
            assert (lo, hi) == (a_lo, a_hi), key
