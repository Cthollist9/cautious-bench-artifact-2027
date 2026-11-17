"""Shim: REMOVAL_VERBS single-source from gen_variants.py (top-level, not a package)."""
import os, sys, importlib.util
_p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "gen_variants.py")
_spec = importlib.util.spec_from_file_location("_gv_shim", _p)
_m = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("_gv_shim", _m)
_spec.loader.exec_module(_m)
REMOVAL_VERBS = _m.REMOVAL_VERBS
verb_polarity = _m.verb_polarity
