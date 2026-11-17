"""Inference + output parsing for real AgentDoG checkpoints.

Each checkpoint is paired with its DOCUMENTED prompt type (see prompts.py) and a
parser matching that output contract. Verdict normalization is lenient (regex
search) so minor extra tokens don't break parsing; unparseable -> "parse_error".
"""
import os, re, json
from typing import Dict, Any

MODELS_ROOT = os.environ.get("MODELS_ROOT", "")

# checkpoint -> (prompt_type, emits_attribution, local_dirname)
SUT_REGISTRY = {
    "AgentDoG1.5-Unified-Qwen3.5-4B": dict(prompt="unified", attr=True,  dir="AgentDoG1.5-Unified-Qwen3.5-4B_ms"),
    "AgentDoG1.5-FG-Qwen3.5-4B":      dict(prompt="fg_diagnosis", attr=True,  dir="AgentDoG1.5-FG-Qwen3.5-4B_ms"),
    "AgentDoG1.5-Qwen3.5-4B":         dict(prompt="coarse",  attr=False, dir="AgentDoG1.5-Qwen3.5-4B_ms"),
    "AgentDoG1.5-FG-Llama-3.1-8B":    dict(prompt="fg_diagnosis", attr=True,  dir="AgentDoG1.5-FG-Llama-3.1-8B_ms2"),
    "AgentDoG-FG-Llama3.1-8B":        dict(prompt="fg",      attr=True,  dir="AgentDoG-FG-Llama3.1-8B_ms"),
    "AgentDoG-FG-Qwen3-4B":           dict(prompt="fg",      attr=True,  dir="AgentDoG-FG-Qwen3-4B_ms"),
    "AgentDoG-FG-Qwen2.5-7B":         dict(prompt="fg",      attr=True,  dir="AgentDoG-FG-Qwen2.5-7B_ms"),
    "AgentDoG1.5-Llama-3.1-8B":       dict(prompt="coarse",  attr=False, dir="AgentDoG1.5-Llama-3.1-8B_ms"),
    "AgentDoG1.5-Qwen3.5-0.8B":       dict(prompt="coarse",  attr=False, dir="AgentDoG1.5-Qwen3.5-0.8B_ms"),
    "AgentDoG1.5-Qwen3.5-2B":         dict(prompt="coarse",  attr=False, dir="AgentDoG1.5-Qwen3.5-2B_ms"),
    "AgentDoG-Qwen3-4B":              dict(prompt="binary",  attr=False, dir="AgentDoG-Qwen3-4B_ms"),
    "AgentDoG-Qwen2.5-7B":            dict(prompt="binary",  attr=False, dir="AgentDoG-Qwen2.5-7B_ms"),
    "AgentDoG-Llama3.1-8B":           dict(prompt="binary",  attr=False, dir="AgentDoG-Llama3.1-8B_ms"),
}

# tool-name -> tool list shown to coarse prompt (taken from the trajectory profile)
def _tool_list(scen):
    m = re.search(r"Available tools:\s*\[([^\]]*)\]", scen["trajectory"]["profile"])
    return m.group(1) if m else scen["tool"]


def build_prompt(sut_cfg, scen, rendered):
    if sut_cfg["prompt"] == "fg":
        from prompts import build_fg_prompt
        return build_fg_prompt(rendered)
    if sut_cfg["prompt"] == "unified":
        from prompts import build_unified_prompt
        return build_unified_prompt(rendered)
    if sut_cfg["prompt"] == "coarse":
        from prompts import build_coarse_prompt
        return build_coarse_prompt(rendered, _tool_list(scen))
    if sut_cfg["prompt"] == "binary":
        from prompts import build_binary_prompt
        return build_binary_prompt(rendered)
    if sut_cfg["prompt"] == "fg_diagnosis":
        from prompts import build_fg_diagnosis_prompt
        return build_fg_diagnosis_prompt(rendered, _tool_list(scen))
    raise ValueError(sut_cfg["prompt"])


# AgentDoG's native coarse-parser, verbatim (Agentic RL/slime_recipe/scripts/
# generate_with_env_server.py:69) -- used for the RL safety reward, so coarse-trained checkpoints
# emit the matched form reliably.
JUDGE_SAFE_PATTERN = re.compile(r"<Judgment>\s*(safe|unsafe)\s*</Judgment>", re.IGNORECASE)


def _strip_think(text):
    """Thinking-mode models emit <think>...</think> before the answer. The opening <think> is a
 chat-template prefix stripped by skip_special_tokens, so only </think> survives in the decoded
 output; strip up to+including the LAST </think>. Mirrors AgentDoG's own strip
 (generate_with_env_server.py:597: re.sub(r"<think(?:ing)?>.*?</think(?:ing)?>", ..., DOTALL))."""
    close = text.rfind("</think>")
    return text[close + len("</think>"):].strip() if close != -1 else text.strip()


def parse_output(prompt_type, text):
    """Parse per the checkpoint's DOCUMENTED output contract (strict -- no lenient fallback).

 Native where AgentDoG ships a parser: coarse = JUDGE_SAFE_PATTERN (their RL reward regex);
 unified = the "Safety: safe|unsafe" line. FG text (Risk Source/Failure Mode/Real World Harm)
 has NO native parser anywhere in AgentDoG (grep returns 0 hits; getting_started only prints
 (trajectory_finegrained.txt §Output): line 1 = 'safe'/'unsafe' ONLY; if unsafe, the next three
 lines are "Risk Source:" / "Failure Mode:" / "Real World Harm:". Unmatched -> "parse_error"."""
    raw_full = text.strip()
    body = _strip_think(raw_full)
    out = {"raw": raw_full, "verdict": "parse_error", "risk_source": None,
           "failure_mode": None, "real_world_harm": None}
    lines = [ln.strip() for ln in body.splitlines()]

    def _field(ln, key):
        return ln.split(":", 1)[1].strip() or None

    if prompt_type == "fg":
        first = next((ln for ln in lines if ln), "")
        if first.lower() in ("safe", "unsafe"):
            out["verdict"] = first.lower()
        for ln in lines:
            low = ln.lower()
            if low.startswith("risk source:"):
                out["risk_source"] = _field(ln, "risk source")
            elif low.startswith("failure mode:"):
                out["failure_mode"] = _field(ln, "failure mode")
            elif low.startswith("real world harm:"):
                out["real_world_harm"] = _field(ln, "real world harm")
    elif prompt_type == "unified":
        m = re.search(r"^Safety:\s*(safe|unsafe)\s*$", body, re.IGNORECASE | re.MULTILINE)
        if m:
            out["verdict"] = m.group(1).lower()
        for ln in lines:
            low = ln.lower()
            if low.startswith("risk source:"):
                out["risk_source"] = _field(ln, "risk source")
            elif low.startswith("failure mode:"):
                out["failure_mode"] = _field(ln, "failure mode")
    elif prompt_type == "coarse":
        m = JUDGE_SAFE_PATTERN.search(body)
        if m:
            out["verdict"] = m.group(1).lower()
    elif prompt_type == "binary":
        first = next((ln for ln in lines if ln), "")
        if first.lower() in ("safe", "unsafe"):
            out["verdict"] = first.lower()
    elif prompt_type == "fg_diagnosis":
        # (diagnosis-only). verdict="diagnosed" iff Risk Source extracted; fields stored for attribution.
        for ln in lines:
            low = ln.lower()
            if low.startswith("failure mode:"):
                out["failure_mode"] = _field(ln, "failure mode")
            elif low.startswith("risk consequence:"):
                out["risk_consequence"] = _field(ln, "risk consequence")
            elif low.startswith("risk source:"):
                out["risk_source"] = _field(ln, "risk source")
        out["verdict"] = "diagnosed" if out.get("risk_source") else "parse_error"
    return out


def load_model(ckpt_name):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    if not MODELS_ROOT:
        raise SystemExit("Set the MODELS_ROOT env var to your checkpoint directory "
                         "(the parent of the AgentDoG *_ms subdirs).")
    cfg = SUT_REGISTRY[ckpt_name]
    path = os.path.join(MODELS_ROOT, cfg["dir"])
    tok = AutoTokenizer.from_pretrained(path)
    # CUDA_VISIBLE_DEVICES is pinned to GPU0 in the local runner; load to CPU then move
    # to GPU directly. Avoids the `accelerate` dependency that device_map="auto" needs.
    model = AutoModelForCausalLM.from_pretrained(path, dtype=torch.bfloat16).to("cuda")
    model.eval()
    return model, tok, cfg


def generate(model, tok, prompt, max_new_tokens=2048, enable_thinking=True):
    # 2048 matches AgentDoG's DEPLOYED generation (evaluator.py:88 max_tokens=2048), not the
    # getting_started tutorial's 512 -- the coarse <Analysis> (4 detailed questions) routinely
    # exceeds 512 and cuts off before </Judgment>. FG/unified output is short, so 2048 is headroom.
    #
    # Thinking mode is CHECKPOINT-NATIVE (empirically determined), not a free choice:
    #  - FG + unified are thinking-trained: they need thinking ON to emit their structured output
    #    (Risk Source:/Failure Mode:/Real World Harm: for FG; <think>..Safety:.. for unified). With
    #    thinking OFF they emit unstructured prose and LOSE the attribution (verified: FG-OFF gives
    #    "unsafe\n<prose>" with no RS/FM lines).
    #  - coarse is thinking-OFF: its template's expected output has no <think>, and it emits a clean
    #    <Analysis>/<Judgment> with thinking OFF.
    # The RL recipe's enable_thinking=False (generate_with_env_server.py) is for the AGENT tool-call
    # rollouts, NOT guardrail eval -- do not import it here. Caller passes enable_thinking per-SUT.
    import torch
    messages = [{"role": "user", "content": prompt}]
    try:
        text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=enable_thinking)
    except TypeError:
        text = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inp = tok([text], return_tensors="pt").to(model.device)
    with torch.no_grad():
        ids = model.generate(**inp, max_new_tokens=max_new_tokens, do_sample=False)
    out_ids = ids[0][len(inp.input_ids[0]):].tolist()
    return tok.decode(out_ids, skip_special_tokens=True).strip()
