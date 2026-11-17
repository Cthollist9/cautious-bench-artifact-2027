# Cautious Bench — anonymous artifact

This package contains the corpus factory, the main corpus, the controlled boards used in
the paper's relation and rule-deletion experiments, the adapters for the seven measured
guardrails, and the scoring code. It is prepared for anonymous review. It contains no
author names, host names, absolute paths, API endpoints, or API keys. Every endpoint,
key, model path, and output directory is read from an environment variable.

## Corpus

`data/main/` holds the corpus under two name tiers and the benign and twin halves:

- `corpus_plain.jsonl` — the plain operational name.
- `corpus_scary.jsonl` — the scary-sounding name.

The two files merge the main factory corpus with the outbound and flow packs. All rows share
the same delivery schema; the pack rows carry their own cell ids.

Each row is one version of one case. The rules permit the benign version and forbid the
twin version. Rows from one case are repeated measurements, not independent samples.

`data/boards/` holds the controlled inputs:

- `crossed/relation_board.jsonl` — the relation inside the clause.
- `direction/direction_board.jsonl` and `direction/direction_placebo.jsonl` — the
  direction word and its placebo.
- `new_relations/audience.jsonl`, `window.jsonl`, `kid.jsonl`, `floor.jsonl` — the four
  new relations.
- `priority/conflict_board.jsonl` — the rule-priority experiment.
- `deletion/deletion_plain.jsonl` and `deletion_scary.jsonl` — the rule-deletion
  corpora.

## Contents

- `gen_neutral_corpora.py`, `gen_variants.py`, `variant_names.py`,
  `delivery_overrides.json`, `src/` — the corpus factory: per-cell authorization rules,
  benign/twin pairs, and name-token variants.
- `packs/outbound/`, `packs/flow/` — the two additional pack generators. They use the same
  factory and row schema as the main corpus. Generation is deterministic and uses only the
  standard library.
- `data/` — the generated corpus and the controlled boards.
- `agentdog/`, `run_agentdog.py` — AgentDoG-Llama and AgentDoG-Qwen.
- `run_tsguard.py` — TS-Guard.
- `guardrails/adapt_adaguard.py` — AdaGuard.
- `guardrails/adapt_agrail.py` and `guardrails/adapt_agrail_relfaces.py` — AGrail.
- `guardrails/adapt_nemo.py` and `guardrails/adapt_nemo_relmain.py` — NeMo Guardrails.
- `run_toolemu_cg.py`, `toolemu_backend.py` — the ToolEmu safety evaluator.
- `adapt_llamaguard.py` — LlamaGuard baseline.
- `scoring/score.py` — the main table, the name effect, the four relation experiments,
  and rule deletion.
- `scoring/extract_reasons.py` — reason extraction for the reason layer.
- `scoring/reason_coding_prompt.md` — the coding prompt.
- `requirements.txt`, `LICENSE` (MIT).

## Setup

Corpus generation needs Python 3.10+ and no third-party packages. Guardrail runs need
the packages in `requirements.txt` and the guardrail's own source and weights. Third-party
code and model weights are not bundled.

| guardrail | source / weights | environment |
|---|---|---|
| AgentDoG-Llama, AgentDoG-Qwen | AgentDoG weights | `MODELS_ROOT` |
| TS-Guard | ToolSafe and TS-Guard weights | `TSGUARD_MODEL`, `TOOLSAFE_DIR` |
| AdaGuard | AdaGuard source and AdaGuard-8B weights | `ADAGUARD_ROOT`, `ADAGUARD_WEIGHTS` |
| AGrail | AGrail source; OpenAI-compatible endpoint and embedding model | `AGRAIL_ROOT`, `AGRAIL_API_BASE`, `AGRAIL_API_KEY`, `AGRAIL_MODEL`, `AGRAIL_EMB_MODEL` |
| NeMo Guardrails | `pip install nemoguardrails==0.24.1`; OpenAI-compatible endpoint | `NEMO_API_BASE`, `NEMO_API_KEY`, `NEMO_MODEL` |
| ToolEmu | ToolEmu and PromptCoder checkouts; OpenAI-compatible endpoint | `TOOLEMU_DIR`, `PYTHONPATH`, `API_BASE`, `API_KEY`, `API_MODEL` |
| LlamaGuard | Llama-Guard-3-8B weights | `LG_MODEL` |

Set `CG_ROOT` to this directory if you run from elsewhere. Results default to
`results/` under it; `CG_RESULTS` overrides that for the slot adapters. No endpoint or
key has a default value.

## Regenerate the corpus

```
python3 gen_neutral_corpora.py
```

The main generator writes the as-authored base and the two name-grade corpora under
`data/main/` by default. The pack generators write their three tiers under their own
directories. The shipped two tier files are the merge of the main corpus and the pack
tiers. Generation is deterministic: no clock, host state, or randomness enters the output.
Set `CG_DATA_ROOT` to write elsewhere.

## Main corpus

The main table uses two name tiers (plain and scary) and the benign and twin halves.
Run five repetitions for every guardrail except AdaGuard (two runs) and LlamaGuard
(baseline, one run).

AdaGuard (four arms; two runs, `--rep 1` and `--rep 2`):

```
python3 guardrails/adapt_adaguard.py --arm native_bt --batch 1 --rep 1 --out results/adaguard/native_bt.rep1.jsonl
python3 guardrails/adapt_adaguard.py --arm native_bt_twin --batch 1 --rep 1 --out results/adaguard/native_bt_twin.rep1.jsonl
python3 guardrails/adapt_adaguard.py --arm native_tt --batch 1 --rep 1 --out results/adaguard/native_tt.rep1.jsonl
python3 guardrails/adapt_adaguard.py --arm native_tt_twin --batch 1 --rep 1 --out results/adaguard/native_tt_twin.rep1.jsonl
```

AGrail (four arms; repeat `--rep 1..5`):

```
python3 guardrails/adapt_agrail.py --arm native_bt --workers 3 --rep 1 --out results/agrail/native_bt.rep1.jsonl
python3 guardrails/adapt_agrail.py --arm native_bt_twin --workers 3 --rep 1 --out results/agrail/native_bt_twin.rep1.jsonl
python3 guardrails/adapt_agrail.py --arm native_tt --workers 3 --rep 1 --out results/agrail/native_tt.rep1.jsonl
python3 guardrails/adapt_agrail.py --arm native_tt_twin --workers 3 --rep 1 --out results/agrail/native_tt_twin.rep1.jsonl
```

NeMo Guardrails (four arms; repeat `--rep 1..5`):

```
python3 guardrails/adapt_nemo.py --arm native_bt --rep 1 --out results/nemo/native_bt.rep1.jsonl
python3 guardrails/adapt_nemo.py --arm native_bt_twin --rep 1 --out results/nemo/native_bt_twin.rep1.jsonl
python3 guardrails/adapt_nemo.py --arm native_tt --rep 1 --out results/nemo/native_tt.rep1.jsonl
python3 guardrails/adapt_nemo.py --arm native_tt_twin --rep 1 --out results/nemo/native_tt_twin.rep1.jsonl
```

AgentDoG (one file per tier and repetition; each file has both halves):

```
CG_SRC_NL=data/main/corpus_plain.jsonl \
CG_RESULTS=results/agentdog_qwen/plain \
python3 run_agentdog.py infer AgentDoG1.5-Qwen3.5-4B --out-suffix .rep1

CG_SRC_NL=data/main/corpus_scary.jsonl \
CG_RESULTS=results/agentdog_qwen/scary \
python3 run_agentdog.py infer AgentDoG1.5-Qwen3.5-4B --out-suffix .rep1
```

Use `AgentDoG1.5-Llama-3.1-8B` for the Llama variant.

TS-Guard (one file per tier and repetition; each file has both halves):

```
TSGUARD_MODEL=/path/to/TS-Guard TOOLSAFE_DIR=/path/to/ToolSafe \
python3 run_tsguard.py \
  --corpus data/main/corpus_plain.jsonl \
  --tag plain --out results/tsguard/plain.rep1.jsonl
```

ToolEmu (one file per tier and repetition; each file has both halves):

```
TOOLEMU_DIR=/path/to/ToolEmu API_BASE=<your-endpoint> API_KEY=... API_MODEL=gpt-oss-120b \
python3 run_toolemu_cg.py --backend openai \
  --corpus data/main/corpus_plain.jsonl \
  --out results/toolemu/plain.rep1.jsonl
```

LlamaGuard baseline (one run per arm):

```
LG_MODEL=/path/to/llama-guard-3-8b python3 adapt_llamaguard.py --arm native_bt --out results/llamaguard/native_bt.jsonl
LG_MODEL=/path/to/llama-guard-3-8b python3 adapt_llamaguard.py --arm native_bt_twin --out results/llamaguard/native_bt_twin.jsonl
LG_MODEL=/path/to/llama-guard-3-8b python3 adapt_llamaguard.py --arm native_tt --out results/llamaguard/native_tt.jsonl
LG_MODEL=/path/to/llama-guard-3-8b python3 adapt_llamaguard.py --arm native_tt_twin --out results/llamaguard/native_tt_twin.jsonl
```

Score the main table:

```
python3 scoring/score.py main \
  --result AdaGuard=native_bt=results/adaguard/native_bt.rep1.jsonl \
  --result AdaGuard=native_bt_twin=results/adaguard/native_bt_twin.rep1.jsonl \
  --result AdaGuard=native_tt=results/adaguard/native_tt.rep1.jsonl \
  --result AdaGuard=native_tt_twin=results/adaguard/native_tt_twin.rep1.jsonl
```

Add further `--result` entries for the other repetitions and guardrails. For a guardrail
whose result file contains both halves (AgentDoG, TS-Guard, ToolEmu), pass the same file
under the benign and twin arm names; the scorer filters by half.

## Name effect

The name effect pairs the plain and scary result files by row id:

```
python3 scoring/score.py name \
  --result TS-Guard=native_bt=results/tsguard/plain.rep1.jsonl \
  --result TS-Guard=native_bt_twin=results/tsguard/plain.rep1.jsonl \
  --result TS-Guard=native_tt=results/tsguard/scary.rep1.jsonl \
  --result TS-Guard=native_tt_twin=results/tsguard/scary.rep1.jsonl
```

## Four relation experiments

The relation experiments use the boards under `data/boards/`. Each guardrail runs one
board at a time.

AdaGuard:

```
python3 guardrails/adapt_adaguard.py --arm e1_board_bt --batch 1 --out results/adaguard/e1_board.jsonl
python3 guardrails/adapt_adaguard.py --arm e2_board_bt --batch 1 --out results/adaguard/e2_board.jsonl
python3 guardrails/adapt_adaguard.py --arm e2_placebo_bt --batch 1 --out results/adaguard/e2_placebo.jsonl
python3 guardrails/adapt_adaguard.py --arm e3_board_bt --batch 1 --out results/adaguard/e3_board.jsonl
python3 guardrails/adapt_adaguard.py --arm ib_audience_bt --batch 1 --out results/adaguard/ib_audience.jsonl
python3 guardrails/adapt_adaguard.py --arm ib_window_bt --batch 1 --out results/adaguard/ib_window.jsonl
python3 guardrails/adapt_adaguard.py --arm ib_kid_bt --batch 1 --out results/adaguard/ib_kid.jsonl
python3 guardrails/adapt_adaguard.py --arm ib_floor_bt --batch 1 --out results/adaguard/ib_floor.jsonl
```

AGrail:

```
python3 guardrails/adapt_agrail_relfaces.py --arm agr_e1_board --out results/agrail/e1_board.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_e2_board --out results/agrail/e2_board.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_e2_placebo --out results/agrail/e2_placebo.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_e3_board --out results/agrail/e3_board.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_ib_audience --out results/agrail/ib_audience.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_ib_window --out results/agrail/ib_window.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_ib_kid --out results/agrail/ib_kid.jsonl
python3 guardrails/adapt_agrail_relfaces.py --arm agr_ib_floor --out results/agrail/ib_floor.jsonl
```

NeMo Guardrails:

```
python3 guardrails/adapt_nemo_relmain.py --arm e1_board --out results/nemo/e1_board.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm e2_board --out results/nemo/e2_board.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm e2_placebo --out results/nemo/e2_placebo.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm e3_board --out results/nemo/e3_board.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm ib_audience --out results/nemo/ib_audience.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm ib_window --out results/nemo/ib_window.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm ib_kid --out results/nemo/ib_kid.jsonl
python3 guardrails/adapt_nemo_relmain.py --arm ib_floor --out results/nemo/ib_floor.jsonl
```

AgentDoG, TS-Guard, and ToolEmu accept the board file directly:

```
CG_SRC_NL=data/boards/crossed/relation_board.jsonl \
CG_RESULTS=results/agentdog_qwen/e1 \
python3 run_agentdog.py infer AgentDoG1.5-Qwen3.5-4B

TSGUARD_MODEL=... TOOLSAFE_DIR=... python3 run_tsguard.py \
  --corpus data/boards/crossed/relation_board.jsonl \
  --tag e1 --out results/tsguard/e1.jsonl

TOOLEMU_DIR=... API_BASE=... API_KEY=... \
python3 run_toolemu_cg.py --backend openai \
  --corpus data/boards/crossed/relation_board.jsonl \
  --out results/toolemu/e1.jsonl
```

Score the crossed design:

```
python3 scoring/score.py crossed \
  --board data/boards/crossed/relation_board.jsonl \
  --result ToolEmu=results/toolemu/e1.jsonl --by-class relation_kind
```

Score the direction word and the placebo:

```
python3 scoring/score.py direction \
  --board data/boards/direction/direction_board.jsonl \
  --placebo data/boards/direction/direction_placebo.jsonl \
  --result ToolEmu=results/toolemu/e2.jsonl \
  --placebo-result ToolEmu=results/toolemu/e2p.jsonl \
  --native-result ToolEmu=results/toolemu/plain.rep1.jsonl
```

Score the four new relations (repeat `--board` and `--result` for each board):

```
python3 scoring/score.py newrelations \
  --board data/boards/new_relations/audience.jsonl \
  --result AdaGuard=results/adaguard/ib_audience.jsonl
```

Score rule priority:

```
python3 scoring/score.py priority \
  --board data/boards/priority/conflict_board.jsonl \
  --result AGrail=results/agrail/e3.jsonl
```

## Rule deletion

AdaGuard, AGrail, and NeMo use their `strip_*` arms; AgentDoG, TS-Guard, and ToolEmu
read the deletion corpora directly.

```
python3 guardrails/adapt_adaguard.py --arm strip_bt --batch 1 --out results/adaguard/strip_bt.jsonl
python3 guardrails/adapt_agrail.py --arm strip_bt --workers 3 --out results/agrail/strip_bt.jsonl
python3 guardrails/adapt_nemo.py --arm strip_bt --out results/nemo/strip_bt.jsonl

CG_SRC_NL=data/boards/deletion/deletion_plain.jsonl \
CG_RESULTS=results/agentdog_qwen/strip \
python3 run_agentdog.py infer AgentDoG1.5-Qwen3.5-4B

TSGUARD_MODEL=... TOOLSAFE_DIR=... python3 run_tsguard.py \
  --corpus data/boards/deletion/deletion_plain.jsonl \
  --tag strip_bt --out results/tsguard/strip_bt.jsonl

TOOLEMU_DIR=... API_BASE=... API_KEY=... \
python3 run_toolemu_cg.py --backend openai \
  --corpus data/boards/deletion/deletion_plain.jsonl \
  --out results/toolemu/strip_bt.jsonl
```

Score deletion:

```
python3 scoring/score.py deletion \
  --native ToolEmu=results/toolemu/plain.rep1.jsonl \
  --strip ToolEmu=results/toolemu/strip_bt.jsonl
```

## Reason layer

`scoring/extract_reasons.py` writes the guardrail's stated reason for every result row.
Code the reasons with `scoring/reason_coding_prompt.md`; the prompt defines the class
sets for false refusal, detection, missed detection, and correct release.

```
python3 scoring/extract_reasons.py \
  --result ToolEmu=results/toolemu/plain.rep1.jsonl \
  --out results/toolemu/reasons_plain.jsonl
```

## Statistical unit

The case is the statistical unit. A row is one version of the input, and rows from one
case are repeated measurements. Paired comparisons use the same case under two
conditions. `scoring/score.py name` reports paired new-only and plain-only counts with
an exact McNemar p-value; the relation subcommands report the refusal-rate differences
defined in the paper.

## Requirements

Corpus generation: Python 3.10+ only. Guardrail runs: see `requirements.txt`. GPU
guardrails need a CUDA device; API guardrails need an OpenAI- or Anthropic-compatible
endpoint. Third-party repositories and weights are not included.

## Anonymity

This package contains no absolute paths, author-identifying hostnames or addresses, and
no credentials. Generation resolves paths relative to the package. Guard endpoints,
keys, and model paths are read from environment variables only. The corpus uses
fictional resources, identifiers, and principals.

## License

MIT. Third-party guardrail code and model weights keep their own licenses.
