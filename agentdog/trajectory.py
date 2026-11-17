"""Render a CONTEXTBENCH scenario into AgentDoG's native trajectory string.

`format_conversation_history` is taken verbatim from
external/AgentDoG/examples/getting_started_v1_5.md so the input the guardrail
sees is exactly what its checkpoint was trained on (no adapter drift).
"""
from typing import Dict


def format_conversation_history(example: Dict) -> str:
    history_parts = []

    if "profile" in example and example["profile"]:
        history_parts.append(f"=== Agent Profile ===\n{example['profile']}\n")

    history_parts.append("=== Conversation History ===")

    for round_idx, round_data in enumerate(example.get("contents", []), 1):
        for turn in round_data:
            role = turn["role"]

            if role == "user":
                if turn.get("content"):
                    history_parts.append(f"\n[USER]: {turn['content']}")

            elif role == "agent":
                agent_parts = []
                for key, value in turn.items():
                    if key != "role" and value:
                        agent_parts.append(f"[{key.upper()}]: {str(value).strip()}")
                if agent_parts:
                    history_parts.append("\n[AGENT]:\n" + "\n".join(agent_parts))

            elif role == "environment":
                if turn.get("content"):
                    history_parts.append(f"\n[ENVIRONMENT]: {turn['content']}")

    return "\n".join(history_parts)


def render_scenario(scen: Dict) -> str:
    """Render a CONTEXTBENCH scenario dict -> AgentDoG trajectory text."""
    return format_conversation_history(scen["trajectory"])


if __name__ == "__main__":
    import json
    scens = json.load(open(__import__("os").path.join(__import__("os").path.dirname(__file__), "data", "scenarios.json")))
    # show one benign + one source for the same action, to eyeball the Ct flip
    for sid in ["delete_file__benign", "delete_file__source"]:
        s = next(x for x in scens if x["id"] == sid)
        print("=" * 70)
        print(s["id"], "| gt:", s["gt_label"], s["gt_flip"], "| RS:", s["gt_risk_source"], "FM:", s["gt_failure_mode"])
        print("-" * 70)
        print(render_scenario(s))
