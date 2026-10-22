---
name: octogent-pentest-redteam
description: >
  Comprehensive penetration testing, red teaming, and bug bounty hunting skill
  integrating 10 specialized tools (Strix, PentestGPT, CAI, PentestAgent, 
  Deadend-CLI, Nebel, HackingBuddyGPT, HexStrike-AI, PentAGI, PentestMCP).
  Use when the user needs to: (1) plan or execute penetration tests, 
  (2) perform red team engagements, (3) conduct bug bounty reconnaissance 
  and exploitation, (4) analyze vulnerabilities with AI assistance, 
  (5) generate security reports, (6) set up CI/CD security pipelines,
  (7) perform OSINT and social engineering assessments, (8) emulate 
  adversary TTPs. Triggers on: pentest, red team, bug bounty, 
  vulnerability assessment, exploitation, C2, phishing, OSINT, 
  adversarial emulation, security audit, offensive security.
---

# OctoGent Pentest & Redteam

Unified offensive security skill combining 10 production-grade and 
experimental AI-augmented pentest/redteam tools.

## Core Philosophy

> *"The future of penetration testing, red teaming, and bug bounties is 
> intertwined. These once-distinct disciplines will merge, forming a 
> cohesive and dynamic approach to security."* — Omar Santos et al.

**Three pillars:**
- **Penetration Testing** — Structured vulnerability identification & verification
- **Red Teaming** — Adversary emulation, full-spectrum engagement
- **Bug Bounty** — Continuous external vulnerability discovery

## Tool Matrix

| Tool | Status | Category | Best For |
|------|--------|----------|----------|
| **Strix** | Production | Orchestration | CI/CD pipelines, continuous validation, reporting |
| **PentestGPT** | Production | AI Agent | Docker-based local LLM analysis, benchmarked exploitation |
| **CAI** | Production | Multi-Agent | Multi-agent recon, tracking, extensible workflows |
| **Nebel** | Production | Local CLI | Ollama/local LLM, resource-efficient, CLI-native |
| **PentestAgent** | Experimental | Playbook Agent | Docker toolchains, MCP integration, playbook-driven |
| **Deadend-CLI** | Experimental | Privacy | Fully offline, air-gapped, privacy-first assessments |
| **HackingBuddyGPT** | Experimental | Research | Academic benchmarks, privacy-focused AI research |
| **HexStrike-AI** | Experimental | MCP Bridge | Large-scale MCP tool orchestration, high-capability ops |
| **PentAGI** | Experimental | Autonomous | Autonomous attack design, limited validation (use with caution) |
| **PentestMCP** | Experimental | Tool Server | Pure MCP tool server, no agent logic (infra component) |

## Engagement Lifecycle

### Phase 0: Scoping & Rules of Engagement (ROE)

**Mandatory before any activity:**
1. Define target scope (IP ranges, domains, exclusions)
2. Set engagement timeline and checkpoints
3. Establish communication protocols (White Cell/Control)
4. Get written authorization ( Statement of Work )
5. Define success criteria and abort conditions

**Legal boundary check:** If authorization is unclear → STOP. Ask user to confirm scope.

### Phase 1: Reconnaissance & OSINT

**Tool selection:** CAI (multi-agent), Nebel (local), Deadend-CLI (offline)

**Sub-phases:**
1. **Passive Recon** — Domain intel, personnel, tech stack
   - DNS enumeration, subdomain discovery
   - Certificate transparency logs
   - Social media profiling, GitHub recon
   - Shodan/Censys queries
2. **Active Recon** — Direct target interaction
   - Port scanning (nmap masscan)
   - Service enumeration
   - Web app fingerprinting
3. **AI-Augmented Analysis**
   - Feed recon data to PentestGPT/Nebel for attack surface analysis
   - Use CAI agents for parallel correlation

**Key technique:** *Watering hole attacks* — Monitor target's public AI/ML platform activity (per book reference, Chapter 1). Seed malicious models on platforms where targets are active.

### Phase 2: Vulnerability Assessment

**Tool selection:** Strix (continuous), PentestGPT (AI analysis), PentestAgent (playbooks)

**Approach:**
1. Automated scanning (vuln scanners, nuclei, etc.)
2. Manual verification of findings
3. AI-assisted prioritization:
   ```
   Feed: vulnerability scan output + asset criticality
   To: PentestGPT / Nebel
   Output: prioritized exploit queue with CVSS + business impact
   ```
4. Continuous validation via Strix CI/CD pipeline

### Phase 3: Exploitation

**Tool selection:** PentestGPT (AI-guided), HexStrike-AI (MCP tools), PentestAgent (playbooks)

**Workflow:**
1. Select target from prioritized queue
2. AI-assisted exploit selection (PentestGPT suggests based on service fingerprint)
3. Execute via MCP-connected tools (HexStrike-AI bridges to toolchains)
4. Validate success/failure, capture evidence
5. Chain to next target

**Critical rule:** Always verify exploit impact — document whether it's a proof-of-concept or full compromise.

### Phase 4: Post-Exploitation

**Tool selection:** PentestAgent (persistence playbooks), HackingBuddyGPT (research)

**Activities:**
1. **Persistence** — Registry keys, scheduled tasks, WMI events, systemd timers
2. **Privilege Escalation** — Local enumeration, kernel exploits, misconfigurations
3. **Lateral Movement** — Pass-the-hash, RDP hijacking, SSH key pivoting
4. **Credential Access** — LSASS dumping, Kerberoasting, DCSync
5. **Data Exfiltration Simulation** — Mark data locations without actual exfiltration
6. **C2 Communication** — Covert channels, domain fronting, DNS tunneling

**AI technique:** Use prompt engineering (per book Chapter 1) to analyze Jupyter notebooks, training pipelines, and ML model code for data poisoning opportunities.

### Phase 5: Reporting & Debrief

**Tool selection:** Strix (reporting), CAI (tracking)

**Report sections:**
1. Executive Summary (risk score, key findings)
2. Technical Findings (vulnerability, evidence, remediation)
3. Attack Path Narrative (chronological TTP walkthrough)
4. MITRE ATT&CK Mapping
5. Remediation Roadmap (prioritized by risk)
6. Appendix (tools used, scope, ROE)

## AI Integration Patterns

### Pattern 1: LLM-Augmented Recon
```
Input: raw recon data (subdomains, ports, banners)
→ Nebel / PentestGPT
Output: structured attack surface with confidence scores
```

### Pattern 2: Autonomous Vuln Analysis
```
Input: vulnerability scanner output
→ PentestGPT (with local LLM via Ollama)
Output: exploitability assessment + suggested next steps
```

### Pattern 3: Multi-Agent Orchestration
```
Input: engagement scope
→ CAI (coordinator agent)
  → Recon agent
  → Exploit agent  
  → Report agent
Output: synchronized engagement data with timeline
```

### Pattern 4: MCP Tool Bridge
```
Input: high-level task ("scan and exploit web app")
→ HexStrike-AI (MCP orchestrator)
  → nmap MCP server
  → nuclei MCP server
  → metasploit MCP server
Output: consolidated results
```

## Safety & Compliance Guardrails

### Absolute Rules
1. **Authorization required** — Never test without explicit written scope
2. **No production disruption** — Avoid denial-of-service unless explicitly scoped
3. **Data handling** — Anonymize all findings; never exfiltrate real PII
4. **Responsible disclosure** — Bug bounty findings via coordinated disclosure
5. **Air-gapped preference** — For sensitive assessments, use Deadend-CLI + local LLM

### Risk Escalation
| Scenario | Action |
|----------|--------|
| Scope ambiguity | Pause, request clarification |
| Critical infra at risk | Abort, notify White Cell immediately |
| Unexpected data access | Stop, document, do not extract |
| AI suggests illegal action | Reject, flag for review |

## Tool-Specific Quick Reference

### Strix (CI/CD + Reporting)
- **Use when:** Continuous security validation, automated reporting
- **Integration:** Plug into CI/CD pipelines; auto-trigger on deployments
- **Key feature:** Continuous validation with benchmark tracking

### PentestGPT (Docker + Local LLM)
- **Use when:** AI-assisted exploit analysis, local/offline operation
- **Setup:** Docker container with Ollama/llama.cpp backend
- **Key feature:** Benchmarked against standard vuln datasets

### CAI (Multi-Agent)
- **Use when:** Complex engagements requiring parallel workstreams
- **Pattern:** Coordinator + specialized agents (recon, exploit, report)
- **Key feature:** Built-in tracking and extensibility

### Nebel (CLI-Native Local)
- **Use when:** Resource-constrained environments, quick CLI workflows
- **Backend:** Ollama or compatible local LLM
- **Key feature:** Minimal resource footprint, shell-native UX

### PentestAgent (Playbooks + MCP)
- **Use when:** Repeatable playbook-driven assessments
- **Pattern:** Define playbooks → auto-execute via MCP tool servers
- **Key feature:** Docker-based toolchains for reproducibility

### Deadend-CLI (Offline-First)
- **Use when:** Air-gapped networks, maximum privacy requirements
- **Constraint:** No external connectivity; all LLM inference local
- **Key feature:** Zero telemetry, full offline capability

### HackingBuddyGPT (Research)
- **Use when:** Academic benchmarks, novel technique research
- **Focus:** Privacy-preserving AI for security research
- **Key feature:** Benchmark suite for comparing AI pentest approaches

### HexStrike-AI (MCP Bridge)
- **Use when:** Large-scale tool orchestration needed
- **Warning:** High capability = high risk; strict scope enforcement required
- **Key feature:** Bridges dozens of tools via MCP protocol

### PentAGI (Autonomous)
- **Use when:** Exploratory autonomous attack design
- **Warning:** Limited validation — outputs must be human-verified
- **Key feature:** Generates novel attack chains autonomously

### PentestMCP (Tool Server)
- **Use when:** Building custom tool integrations
- **Pattern:** Deploy as MCP server, connect via HexStrike-AI or PentestAgent
- **Key feature:** Standardized tool interface (no agent logic)

## Cross-Reference: Book Chapters → Tools

| Book Chapter | Primary Tools | Skill Area |
|--------------|--------------|------------|
| Ch 1: Evolution | All | Strategic planning |
| Ch 2: Red Team Intro | CAI, Strix | Framework selection |
| Ch 3: Infrastructure | PentestAgent, HexStrike-AI | C2 setup |
| Ch 4: Methodology | Strix, PentestGPT | TTP execution |
| Ch 5: Social Engineering | PentestGPT, CAI | Phishing, pretexting |
| Ch 6: Post-Exploitation | PentestAgent, HackingBuddyGPT | Persistence, lateral movement |
| Ch 7: AD/Linux | HexStrike-AI, PentestMCP | Domain enumeration |
| Ch 8: AI Revolution | PentestGPT, Nebel, PentAGI | AI-powered tooling |
| Ch 9: Bug Bounty | CAI, Strix | Recon, reporting |
| Ch 10: Web/API Hacking | PentestAgent, HexStrike-AI | App exploitation |
| Ch 11: AI Automation | All AI tools | Autonomous workflows |

## Getting Started

1. **Quick scan:** `Nebel` or `Deadend-CLI` for fast, local assessment
2. **Full engagement:** `CAI` multi-agent + `Strix` reporting pipeline
3. **CI/CD security:** `Strix` continuous validation + `PentestAgent` playbooks
4. **Research mode:** `HackingBuddyGPT` benchmarks + `PentAGI` novel chains
5. **MCP ecosystem:** `HexStrike-AI` orchestrator + `PentestMCP` tool servers

Read [references/tool-details.md](references/tool-details.md) for per-tool deep-dive.
Read [references/ttp-library.md](references/ttp-library.md) for MITRE ATT&CK mapped techniques.
Read [references/ai-prompts.md](references/ai-prompts.md) for LLM prompt templates.
