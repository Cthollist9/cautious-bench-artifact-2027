"""
The host env upgraded langchain/pydantic past ToolEmu's 2023 pins; toolemu_backend only needs
the PROMPT OBJECTS (agent_safe_evaluator), whose construction uses procoder alone — the heavy

Stubs (display-only helpers, provably unused in prompt construction — agent_safe_evaluator.py
lines 333-335 use them only under __main__):
 toolemu / toolemu.prompts / toolemu.prompts.evaluator — namespace modules with __path__ set,
 so the real prompt .py files load without executing the package __init__s;
 toolemu.utils — dummy providing get_num_tokens/make_colorful no-ops.

Usage: `import cg_eval_shim` BEFORE importing toolemu_backend / run_toolemu_cg.
"""
import sys, types
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "external_repos" / "ToolEmu" / "toolemu"

def _ns(name, path):
    m = types.ModuleType(name)
    m.__path__ = [str(path)]
    sys.modules[name] = m
    return m

if "toolemu" not in sys.modules:
    _ns("toolemu", _T)
if "toolemu.utils" not in sys.modules:
    u = types.ModuleType("toolemu.utils")
    u.get_num_tokens = lambda s: len(str(s)) // 4
    u.make_colorful = lambda tag, text, **k: str(text)
    sys.modules["toolemu.utils"] = u
if "toolemu.prompts" not in sys.modules:
    _ns("toolemu.prompts", _T / "prompts")
if "toolemu.prompts.evaluator" not in sys.modules:
    _ns("toolemu.prompts.evaluator", _T / "prompts" / "evaluator")
