<div align="center">
  <img src="assets/logo.png" alt="SkillAttack logo" width="220" />

  **Automated red teaming of agent skills through attack path refinement.**

  <a href="skillattack_paper.pdf"><img src="https://img.shields.io/badge/📄_Paper-PDF-b31b1b" /></a>&nbsp;
  <a href="https://YOUR_USERNAME.github.io/SkillAttack"><img src="https://img.shields.io/badge/🌐_Showcase-Live_Demo-blue" /></a>&nbsp;
  <a href="#quick-start"><img src="https://img.shields.io/badge/🚀_Quick_Start-Guide-2ea44f" /></a>&nbsp;
  <a href="#citation"><img src="https://img.shields.io/badge/📝_Citation-BibTeX-orange" /></a>

</div>


## Why SkillAttack

As general-purpose agent platforms like OpenClaw adopt **skills** as a core extension mechanism, poorly designed, misconfigured, or malicious skills can directly introduce risks into the agent's execution chain.

The current community largely relies on **manual skill review** or **system-level restrictions** (sandboxing, allowlists) to mitigate these risks. Both approaches have fundamental limitations:

- **Manual review** doesn't scale and misses adversarial edge cases that only surface during execution.
- **System-level restrictions** reduce risk but sacrifice extensibility, often blocking legitimate capabilities alongside dangerous ones.

SkillAttack takes a third path: **automated, evidence-based red teaming**. Rather than guessing what might go wrong, it discovers attack surfaces, generates adversarial prompts, executes them in real sandboxes, judges outcomes from actual execution artifacts, and feeds evidence back into the next attack round. The result is a reproducible vulnerability report grounded in what the agent *actually did*, not what we *assumed* it would do.


## Overview

SkillAttack is the first red-teaming framework that dynamically verifies skill vulnerability exploitability through adversarial prompting, without modifying the skill itself. It operates as a three-stage closed-loop pipeline: **(1) Skill Vulnerability Analysis** identifies attack surfaces from the skill's code and instructions; **(2) Surface-Parallel Attack Generation** constructs adversarial prompts across multiple surfaces simultaneously; **(3) Feedback-Driven Exploit Refinement** executes prompts in sandboxed agents, judges outcomes from real artifacts, and refines attack paths based on execution feedback.

<div align="center">
  <img src="assets/overall.png" alt="SkillAttack overview" width="850" />
</div>


## Quick Start

**Requirements:** Python 3.10+, Docker, an OpenAI-compatible model endpoint.

```bash
git clone https://github.com/YOUR_USERNAME/SkillAttack.git
cd SkillAttack
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Create a `.env` file with your model credentials, then run:

```bash
chmod +x quickstart.sh
./quickstart.sh          # smoke test (1 skill / 1 lane / 1 round)
./quickstart.sh main     # full main experiment
./quickstart.sh compare  # SkillInject comparison experiment
```

The script handles dependency sync, A.I.G analyzer startup, sandbox setup, and experiment execution.


## Usage

```bash
# Main experiment — run all skills
python main.py main
python main.py main --collect-all-surfaces    # test all surfaces, don't stop early

# Single skill
python scripts/run_single_skill_test.py 001_pskoett_self-improving-agent

# Multi-model — same skill across different LLMs
python scripts/run_multi_model_test.py 001_pskoett_self-improving-agent

# Batch — all skills with cached analyzer results
python scripts/run_all_cached_skills.py --model all

# Comparison — SkillInject baseline
python main.py compare --split obvious --max-cases 20 --repeats 1
```


## Configuration

All settings live in three YAML files under `configs/`:

- **`experiment.yaml`** — experiment parameters: skill directories, iteration budget, parallelism, output paths.
- **`models.yaml`** — named model profiles (provider, endpoint, temperature) referenced by each stage.
- **`stages.yaml`** — binds each pipeline stage (analyzer, attacker, simulator, judge, feedback) to its model profile, prompt, and runtime parameters.

Model credentials should be set via `.env`, not committed to YAML files.


## Datasets

- **SkillInject** (`data/skillinject/`) — 71 adversarial skills in two splits: `obvious/` (explicit injections) and `contextual/` (dual-use instructions).
- **Hot100** (`data/hot100skills/`) — the 100 most popular skills from ClawHub. Download via `python scripts/download_clawhub_hot100.py`.
- **Custom** — place a directory with `SKILL.md` anywhere and set `main.raw_skill_root` in `experiment.yaml`.


## Result Structure

```
result/
├── runs_organize/
│   └── main/<skill_id>/
│       ├── model.json                     # which models ran each stage
│       ├── <skill_id>_analyze.json        # surfaces found
│       ├── surface_01_<name>/round_*.json # per-round evidence chain
│       └── <skill_id>_global_report.json  # per-skill summary
├── log/
└── aig_cache/                             # cached A.I.G analyzer results
```

Each `round_*.json` contains the attack prompt, simulation trace, judge verdict, and feedback.


## Citation

```bibtex
@article{duan2026skillattack,
  title     = {SkillAttack: Automated Red Teaming of Agent Skills through Attack Path Refinement},
  author    = {Zenghao Duan and Yuxin Tian and Liang Pang and Jingcheng Deng and Zihao Wei and Shicheng Xu and Yuyao Ge and Wenbin Duan and Zhiyi Yin and Xueqi Cheng},
  journal   = {arXiv preprint arXiv:xxxx.xxxxx},
  year      = {2026}
}
```


## License

[MIT](LICENSE)
