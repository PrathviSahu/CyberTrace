# CyberTrace — Technical Judge Q&A Playbook

**BharatCode Grand Finale & Showcase**  
**Repository Baseline:** `main` at commit [`1024c6f`](https://github.com/PrathviSahu/CyberTrace/commit/1024c6f)  
**Target Duration:** 4-Minute Presentation + 3-Minute Technical Jury Q&A  

---

## 1. Core Architecture & Problem Statement

### Q1: What specific problem does CyberTrace solve?
> **Answer:**  
> CyberTrace unifies security telemetry ingestion, normalization, deterministic detection, incident graph correlation, investigation, and detection-rule governance into a single continuous analyst workflow. In traditional SOC operations, analysts face fragmentation between detecting suspicious activity in log queries and engineering tested, peer-reviewed detection rules. CyberTrace closes this loop: an analyst hunts, validates the hypothesis against historical benchmark replay, drafts a detection rule, passes it through mandatory four-eyes review, and activates it—all with continuous incident correlation and verifiable audit integrity.

### Q2: Why use deterministic detection alongside Generative AI?
> **Answer:**  
> Our deterministic detection engine produces repeatable, rule-based results. AI is used separately for evidence-grounded investigation and contextual analysis. This separation means an AI-generated explanation does not independently determine whether an alert fires or whether a rule becomes active. Every AI-generated claim is validated against retrieved event citations; hypotheses and unknowns are strictly decoupled from observed facts. Furthermore, if the AI provider experiences latency, rate limits, or network unreachability, CyberTrace automatically fails over to an internal deterministic fallback engine, ensuring the investigation workflow remains fully operational.

---

## 2. Telemetry Ingestion & Truth in Provenance

### Q3: How do you know whether telemetry is real or synthetic?
> **Answer:**  
> CyberTrace classifies telemetry provenance into four distinct states: `observed_telemetry`, `synthetic_benchmark`, `unknown`, or `mixed`.  
> Generic log uploads cannot claim authenticated observed provenance merely by including fields such as `collector_id`, `sensor_id`, or `verified_source: true` in the JSON payload. Because CyberTrace currently operates in a standalone environment without an authenticated agent collector daemon, generic user uploads are strictly classified as `unknown` (or `synthetic_benchmark` if explicitly labeled). Observed telemetry status is cryptographically reserved for server-authenticated collector sessions.

### Q4: Are your benchmark results based on real-world attacks?
> **Answer:**  
> The ThreatLab scenarios (e.g., `SCN-004`) are synthetic benchmark scenarios modeled on realistic MITRE ATT&CK patterns (credential access, privilege escalation, command-and-control beaconing). They provide deterministic, repeatable test cases for measuring detection recall and false positive rates. For instance, the zero-false-positive result shown during the demo is the measured outcome for that specific synthetic benchmark run under controlled conditions; it is not a blanket guarantee of zero false positives in dynamic production environments. We deliberately do not present benchmark replays as proof of real-world detection efficacy across arbitrary enterprise fleet environments.

---

## 3. Detection Engineering & Four-Eyes Governance

### Q5: Can the AI activate detection rules automatically?
> **Answer:**  
> **No.** The AI investigation assistant operates in a strictly read-only advisory capacity and has zero privilege to create, modify, or activate detection rules. Rule creation requires human analyst initiation, and rule activation strictly requires independent peer approval through our four-eyes governance state machine.

### Q6: How does Four-Eyes Governance work in CyberTrace?
> **Answer:**  
> When an analyst creates a detection rule draft from a saved hunt, the rule AST is validated for syntax and schema compliance. To transition a draft from `pending_review` to `active`, a separate reviewer must approve it. The approval is cryptographically bound to the specific `draft_revision_id` and the rule AST state hash; any modification resets the approval status.  
> *Boundary Disclosure:* Inside CyberTrace, this workflow enforces distinct reviewer identity roles (`secops_reviewer_02` cannot be the author). In this standalone showcase, reviewer identities are verified caller-supplied identities rather than enterprise SSO tokens (e.g., Okta/SAML).

### Q7: Does activating a rule block an attacker on the network?
> **Answer:**  
> **No.** Activating a rule enables it within CyberTrace’s internal event processing engine for real-time and replay telemetry matching. CyberTrace is an incident detection, correlation, and response governance platform, not an endpoint detection and response (EDR) kernel agent or inline firewall. It generates correlated detections and triggers containment recommendations that require human authorization.

---

## 4. Integrity, Audit Ledger & Engine Internals

### Q8: Is your audit ledger immutable?
> **Answer:**  
> It is an application-level, append-only audit ledger with SHA-256 state hashing across every rule lifecycle transition (draft, edit, validation, approval, activation, deprecation). It provides robust change-integrity verification and non-repudiation within the application layer. However, we explicitly disclose that it is not backed by hardware-enforced WORM (Write Once, Read Many) storage or distributed blockchain consensus.

### Q9: How is the detection rule AST evaluated safely without arbitrary code execution?
> **Answer:**  
> Custom rules are represented as an Abstract Syntax Tree (AST) supporting boolean logic (`AND`, `OR`, `NOT`) and field comparators (`EQUALS`, `CONTAINS`, `GREATER_THAN`, `IN`). The engine evaluates this AST using a pure Python recursive visitor pattern with zero reliance on `eval()`, `exec()`, or dynamic scripting runtimes, eliminating remote code execution vulnerabilities in rule definitions.

### Q10: What happens if the Gemini/AI provider experiences an outage during an active incident?
> **Answer:**  
> The `InvestigationService` wraps model calls in an isolated resilience handler. If the external provider times out, returns HTTP 5xx, or experiences connection resets, CyberTrace instantaneously fails over to the `DeterministicFallbackEngine`. The fallback engine generates a structured report with observed facts, conservative hypotheses, telemetry unknowns, and impact-assessed containment actions with sub-second in-memory execution (typically under 5 milliseconds), ensuring analysts are never blocked.

---

## 5. Quick-Reference Jury Alignment Matrix

| Question Area | Common Pitfall / Oversell | Calibrated Truthful Position |
| :--- | :--- | :--- |
| **Deterministic vs. AI** | Claiming "Zero-hallucination detections across the board" | Deterministic engine produces repeatable, rule-based results; AI provides contextual analysis without controlling alerting or activation |
| **Telemetry Provenance** | Claiming synthetic uploads are "real live production telemetry" | Truthfully labeled as `unknown` or `synthetic_benchmark` |
| **Benchmark Accuracy** | Claiming "Proven zero false positives in production" | Zero false positives on SCN-004 reflects that specific benchmark run under controlled conditions |
| **Autonomous Action** | Claiming "AI autonomously blocks threats in real-time" | AI only synthesizes evidence; human approvals required; rules run deterministically |
| **Audit Ledger** | Claiming "Cryptographically unhackable blockchain audit trail" | Application-level append-only ledger with SHA-256 state hashing |
| **Rule Activation** | Claiming "Instant fleet-wide endpoint firewall enforcement" | Activates within CyberTrace's engine; alerts SOC analysts and updates incident graph |
| **Identity Verification**| Claiming "Enterprise Zero-Trust IAM integration" | Rigorous four-eyes state machine enforcing distinct identities; demo uses caller-supplied roles |
| **Fallback Latency** | Quoting "0.0 ms" precision | Sub-second in-memory local heuristic execution, typically under 5 ms |
