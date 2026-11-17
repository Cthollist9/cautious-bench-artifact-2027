"""Prompt builders for each AgentDoG checkpoint.

Every prompt is read VERBATIM from AgentDoG's own template files under
external/AgentDoG/prompts/ (no hand-written prompt text). Each checkpoint is
paired with its DOCUMENTED prompt (README warns checkpoints and prompt formats
must match):

"""
import os

# Self-contained: prompts live IN THIS PACKAGE (./prompts/, migrated from AgentDoG's repo so the
# benchmark instance has no agent-harness/external dependency). Verbatim AgentDoG templates.
_PROMPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts")

_TAXONOMY = open(os.path.join(_PROMPTS, "v1.0", "taxonomy_finegrained.txt")).read().strip()
_FG_TEMPLATE = open(os.path.join(_PROMPTS, "v1.0", "trajectory_finegrained.txt")).read()
_BINARY_TEMPLATE = open(os.path.join(_PROMPTS, "v1.0", "trajectory_binary.txt")).read()
_UNIFIED_TEMPLATE = open(os.path.join(_PROMPTS, "v1.5", "unified_safety_classification.txt")).read()
_COARSE_TEMPLATE = open(os.path.join(_PROMPTS, "v1.5", "coarse_grained_moderation.txt")).read()
# this is the AUTHORITATIVE prompt for AgentDoG1.5-FG-*: diagnosis-only, NO safe/unsafe).
_FG_DIAGNOSIS_TEMPLATE = open(os.path.join(_PROMPTS, "v1.5", "fg_diagnosis.txt")).read()


def build_fg_prompt(rendered_trajectory: str) -> str:
    return _FG_TEMPLATE.format(taxonomy=_TAXONOMY, trajectory=rendered_trajectory)


def build_binary_prompt(rendered_trajectory: str) -> str:
    """.0 binary coarse prompt (AgentDoG-Qwen3-4B / Qwen2.5-7B / Llama3.1-8B): 'Print only safe or unsafe'."""
    return _BINARY_TEMPLATE.format(trajectory=rendered_trajectory)


def build_unified_prompt(rendered_trajectory: str) -> str:
    return _UNIFIED_TEMPLATE.format(formatted_trajectory=rendered_trajectory)


def build_coarse_prompt(rendered_trajectory: str, tool_list_text: str) -> str:
    return _COARSE_TEMPLATE.format(formatted_trajectory=rendered_trajectory, tool_list_text=tool_list_text)


def build_fg_diagnosis_prompt(rendered_trajectory: str, tool_list_text: str) -> str:
    """ Diagnosis-ONLY (assumes the trajectory is unsafe) — no safe/unsafe verdict. Used for 2-stage
 attribution (run on the coarse/unified-flagged-unsafe set), NOT for FP measurement."""
    return _FG_DIAGNOSIS_TEMPLATE.format(formatted_trajectory=rendered_trajectory, tool_list_text=tool_list_text)
