# AI Prompt Firewall — Threat Model

## 1. System Overview

The AI Prompt Firewall is a transparent proxy server positioned between client applications and LLM APIs. It inspects every user prompt through three independent detection layers before allowing it to reach the language model.

**Trust boundary:** The firewall sits at the boundary between untrusted user input and the trusted LLM backend. All user-supplied content is treated as potentially adversarial.

## 2. Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|------------|
| External attacker | Crafts adversarial prompts via the client interface | Extract system prompts, bypass content policies, exfiltrate data |
| Insider user | Has legitimate access but sends PII or probes safety limits | Data leakage (accidental or intentional), policy circumvention |
| Automated agent | Programmatic prompt submission at scale | Fuzzing for bypasses, credential extraction, model manipulation |
| Supply chain | Compromised tool outputs fed back as prompts (indirect injection) | Hijack model behavior through poisoned context |

## 3. Attack Surface

### 3.1 Prompt Input Channel
- **Direct injection:** Explicit override commands ("ignore previous instructions")
- **Indirect injection:** Adversarial content embedded in tool outputs, RAG documents, or user-uploaded files that the LLM processes
- **Multi-turn manipulation:** Gradually shifting model behavior across conversation turns
- **Encoding attacks:** Base64, hex, Unicode homoglyphs, ROT13 to evade text filters

### 3.2 System Prompt Extraction
- Direct requests ("show your system prompt")
- Side-channel extraction (encoding instructions in structured output)
- Behavioral probing (testing what the model refuses to infer rules)

### 3.3 Data Exfiltration
- User accidentally sends PII (SSN, CC numbers, medical data) to LLM
- Attacker crafts prompts to make the LLM reveal training data or other users' context

## 4. Detection Coverage Matrix

| Attack Vector | Rule Engine | PII Detector | Semantic Layer | Combined |
|---------------|:-:|:-:|:-:|:-:|
| "Ignore previous instructions" | ✅ | — | ✅ | **Strong** |
| DAN/jailbreak variants | ✅ | — | ✅ | **Strong** |
| System prompt extraction | ✅ | — | ✅ | **Strong** |
| PII in prompt (SSN, CC) | — | ✅ | — | **Strong** |
| Delimiter injection ([INST], <<SYS>>) | ✅ | — | — | **Moderate** |
| Paraphrased injection (novel wording) | ❌ | — | ✅ | **Moderate** |
| Base64/hex encoded payload | ✅ | — | ⚠️ | **Moderate** |
| Emotional manipulation (grandma) | ✅ | — | ✅ | **Moderate** |
| Multilingual injection | ❌ | ❌ | ⚠️ | **Weak** |
| Homoglyph/Unicode obfuscation | ❌ | ❌ | ⚠️ | **Weak** |
| Multi-turn gradual poisoning | ❌ | ❌ | ❌ | **None** |
| Indirect injection (via tools) | ❌ | ❌ | ❌ | **None** |
| Image-based injection | ❌ | ❌ | ❌ | **None** |

## 5. Risk Assessment

### High Risk — Addressed
- **Prompt injection (direct):** Primary use case. Three-layer coverage.
- **PII leakage:** Presidio catches structured PII with high accuracy.
- **Jailbreak (known patterns):** Extensive rule set + semantic fallback.

### Medium Risk — Partial Coverage
- **Novel/paraphrased attacks:** Semantic layer provides coverage, but similarity threshold tuning creates a precision/recall tradeoff. Lower threshold = more false positives.
- **Encoding evasion:** Rule engine catches explicit base64/hex patterns. Semantic layer may catch decoded meaning if obfuscation is light. Heavy obfuscation bypasses both.

### High Risk — Not Addressed
- **Multi-turn attacks:** No conversation state tracking. Each prompt is evaluated independently.
- **Indirect injection:** No scanning of LLM responses or tool outputs.
- **Multimodal injection:** No image/audio analysis.

## 6. Bypass Rate Methodology

The red team runner (`scripts/red_team_runner.py`) evaluates the firewall against a curated dataset of 30 prompts (22 attacks, 8 benign) across three difficulty levels.

**Metrics reported:**
- **Bypass rate** = False Negatives / (True Positives + False Negatives)
- **False positive rate** = False Positives / (True Negatives + False Positives)
- **Per-category detection rate**
- **Per-difficulty breakdown**

Target: Bypass rate below 15% on the included dataset. Production systems should continuously expand the red team dataset and re-evaluate after every rule or model change.

## 7. Hardening Recommendations

1. **Unicode normalization** — Preprocess all input through NFKC normalization before scanning to defeat homoglyph attacks
2. **Conversation-level analysis** — Track prompt sequences per session, flag escalating manipulation patterns
3. **Response scanning** — Apply the same detection layers to LLM output to catch indirect injection effects
4. **Rate limiting** — Limit requests per client to prevent automated fuzzing
5. **Multilingual models** — Replace `all-MiniLM-L6-v2` with `paraphrase-multilingual-MiniLM-L12-v2` for non-English coverage
6. **Canary tokens** — Embed unique tokens in system prompts; if they appear in output, extraction has occurred
7. **Ensemble threshold tuning** — Use the red team dataset to optimize per-layer thresholds via grid search
