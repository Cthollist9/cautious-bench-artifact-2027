"""Custom check action for the action rail (input-rail wiring).

Mirrors the library's self_check_input action
(nemoguardrails/library/self_check/input_check/actions.py) with the checked
object changed from the bare user input to the protected agent's PENDING
ACTION, judged against the deployment policy that lives in prompts.yml
(task check_pending_action; policy slot {{ policy_text }}). Uses the same
taskmanager render/parse machinery and the same fail-closed semantics.
"""
import logging
from typing import Any, Dict, List, Optional

from nemoguardrails import RailsConfig
from nemoguardrails.actions.actions import action
from nemoguardrails.actions.llm.utils import get_last_user_utterance
from nemoguardrails.actions.rail_outcome import RailOutcome
from nemoguardrails.context import llm_call_info_var
from nemoguardrails.llm.call import llm_call
from nemoguardrails.llm.taskmanager import LLMTaskManager
from nemoguardrails.logging.explain import LLMCallInfo
from nemoguardrails.types import LLMModel

import hooks

log = logging.getLogger(__name__)

TASK = "check_pending_action"


@action(is_system_action=True)
async def check_pending_action(
    llm_task_manager: LLMTaskManager,
    llm: Optional[LLMModel] = None,
    context: Optional[dict] = None,
    events: Optional[List[dict]] = None,
    config: Optional[RailsConfig] = None,
    **kwargs,
) -> RailOutcome:
    """Check the pending action against the policy in prompts.yml.

    Returns RailOutcome.allow() if the action is allowed, RailOutcome.block()
    otherwise (fail-closed: empty/failed/unparsable LLM output blocks).
    """
    ctx = context or {}
    # Last user message = the corpus's user request (verbatim); fallback to
    # the driver-supplied context slot (same string) if events are empty.
    user_input = None
    try:
        user_input = get_last_user_utterance(events or [])
    except Exception:
        user_input = None
    if not user_input:
        user_input = ctx.get("user_request")

    policy_text = ctx.get("policy_text") or ""
    observations = ctx.get("observations") or ""
    pending_action = ctx.get("pending_action") or ""

    if not pending_action:
        return RailOutcome.block()

    prompt_context = {
        "user_input": user_input or "",
        "policy_text": policy_text,
        "observations": observations,
        "pending_action": pending_action,
    }

    prompt = llm_task_manager.render_task_prompt(
        task=TASK, events=events, context=prompt_context
    )
    stop = llm_task_manager.get_stop_tokens(task=TASK)
    task_max_tokens = llm_task_manager.get_max_tokens(task=TASK) or 1024

    llm_call_info_var.set(LLMCallInfo(task=TASK))
    llm_response = await llm_call(
        llm,
        prompt,
        stop=stop,
        llm_params={
            "temperature": config.lowest_temperature if config is not None else 0.0,
            "max_tokens": task_max_tokens,
        },
    )
    response = llm_response.content

    if llm_task_manager.has_output_parser(TASK):
        result = llm_task_manager.parse_task_output(TASK, output=response)
    else:
        result = llm_task_manager.parse_task_output(
            TASK, output=response, forced_output_parser="is_content_safe"
        )
    allowed = bool(result[0])

    log.info(f"Pending-action check result is: `{response}` -> allowed={allowed}")
    hooks.record(
        {
            "task": TASK,
            "prompt": prompt,
            "raw_response": response,
            "parsed_allowed": allowed,
            "violations": [str(v) for v in result[1:]],
            "model": getattr(llm_response, "model", None),
            "finish_reason": getattr(llm_response, "finish_reason", None),
            "n_output_tokens": getattr(llm_response, "n_output_tokens", None),
        }
    )
    return RailOutcome.allow() if allowed else RailOutcome.block()
