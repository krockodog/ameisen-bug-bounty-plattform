# Tool Deep-Dive Reference

## Strix (Production)
**Category:** Orchestration & CI/CD  
**Score:** 57/100 (highest overall)

### Capabilities
- Continuous security validation pipelines
- Automated report generation with customizable templates
- Integration with CI/CD (GitHub Actions, GitLab CI, Jenkins)
- Benchmark tracking over time
- Multi-tool result correlation

### When to Use
- Setting up continuous security monitoring
- Enterprise environments with existing DevOps pipelines
- Compliance reporting (SOC2, ISO 27001, PCI-DSS)
- Regression testing after patches

### Integration Pattern
```yaml
# Example CI/CD pipeline snippet
stages:
  - security-scan
  
strix-continuous-validation:
  stage: security-scan
  image: strix/pentest-orchestrator:latest
  script:
    - strix scan --target $DEPLOYMENT_URL --profile ci-cd
    - strix report --format sarif --output security-report.sarif
  artifacts:
    reports:
      sast: security-report.sarif
```

### Key Commands
- `strix scan --target <url> --profile <profile>`
- `strix validate --previous-report <file> --current-report <file>`
- `strix report --format <html|pdf|sarif|json>`

---

## PentestGPT (Production)
**Category:** AI-Powered Analysis  
**Score:** 54/100

### Capabilities
- Docker-contained local LLM for security analysis
- Benchmarked against CVE datasets and CTF challenges
- Exploit suggestion based on service fingerprinting
- Report generation with remediation advice
- Offline operation via local model weights

### When to Use
- Analyzing vulnerability scan output
- Brainstorming exploitation paths
- Writing penetration test reports
- Air-gapped environments (with local model)

### Setup
```bash
# Standard deployment
docker run -p 8080:8080 -v ./models:/models pentestgpt/pentestgpt:latest

# With local LLM (Ollama)
docker run --network=host -e LLM_PROVIDER=ollama \
  -e OLLAMA_URL=http://localhost:11434 \
  pentestgpt/pentestgpt:latest
```

### Key Workflows
1. **Vuln Analysis:** Feed Nessus/OpenVAS XML → get prioritized exploit list
2. **Exploit Chain:** Describe target → receive step-by-step exploitation guide
3. **Report Draft:** Paste findings → generate executive + technical sections

---

## CAI - Cybersecurity AI (Production)
**Category:** Multi-Agent System  
**Score:** 54/100

### Capabilities
- Multi-agent coordination (recon, exploit, report agents)
- Built-in state tracking across engagement timeline
- Extensible agent architecture (custom agents via plugins)
- Shared knowledge graph between agents
- Automatic evidence collection and correlation

### When to Use
- Large-scale engagements requiring parallel workstreams
- Complex multi-domain assessments (web + infra + cloud)
- Team coordination with role separation
- Long-running engagements (weeks/months)

### Agent Architecture
```
Coordinator Agent
├── Recon Agent (subdomain, port, service discovery)
├── Web Agent (app vulns, API testing)
├── Infra Agent (network, AD, cloud)
├── Exploit Agent (payload delivery, exploitation)
└── Report Agent (evidence correlation, report drafting)
```

### Key Commands
- `cai init --engagement <name> --scope <file>`
- `cai agent spawn --type recon --target <domain>`
- `cai status --engagement <name>`
- `cai correlate --findings` (cross-agent intelligence fusion)

---

## Nebel (Production)
**Category:** CLI-Native Local LLM  
**Score:** 45/100

### Capabilities
- Native shell integration (works like a regular CLI tool)
- Ollama integration for local LLM inference
- Extremely resource-efficient (runs on Raspberry Pi)
- No Docker required — single binary
- Fast startup for quick queries

### When to Use
- Quick ad-hoc security questions
- Resource-constrained environments
- Operators who prefer CLI over web UI
- Scripting and automation (pipe recon data to Nebel)

### Shell Integration
```bash
# Direct query
nebel "analyze this nmap output for vulnerabilities" < scan.xml

# In pipeline
subfinder -d target.com | nebel "find interesting subdomains for bug bounty"

# Interactive mode
nebel --interactive
> What webshell techniques work against PHP-FPM?
```

### Key Flags
- `--model <model>`: Specify Ollama model (default: mistral)
- `--format <json|markdown>`: Structured output
- `--context <file>`: Load previous context

---

## PentestAgent (Experimental)
**Category:** Playbook-Driven Agent  
**Score:** 51/100

### Capabilities
- YAML-defined playbooks for repeatable assessments
- MCP (Model Context Protocol) tool integration
- Docker-based toolchains (pre-packaged tool containers)
- Step-by-step execution with rollback capability
- Evidence collection at each step

### When to Use
- Repeatable compliance assessments
- Standardized internal security audits
- Teams with playbook-driven workflows
- Integrating custom tools via MCP

### Playbook Example
```yaml
# playbook-web-app.yaml
name: Web Application Security Assessment
version: 1.0
steps:
  - name: Reconnaissance
    tool: subfinder
    args: [-d, "{{target.domain}}"]
  - name: Port Scan
    tool: nmap
    args: [-sV, "{{target.host}}"]
  - name: Vulnerability Scan
    tool: nuclei
    args: [-u, "{{target.url}}"]
  - name: AI Analysis
    tool: pentestgpt
    input: "{{steps.vulnerability_scan.output}}"
```

### Key Commands
- `pentestagent playbook run <playbook.yaml> --vars target=example.com`
- `pentestagent mcp register --server <mcp-server-url>`
- `pentestagent rollback --step <n>`

---

## Deadend-CLI (Experimental)
**Category:** Privacy-First Offline Tool  
**Score:** 47/100

### Capabilities
- Fully offline operation (no network calls)
- Local LLM inference without cloud dependency
- Zero telemetry and logging
- GPG-encrypted result storage
- Runs on air-gapped systems

### When to Use
- Classified/sensitive environments
- Maximum privacy requirements
- Air-gapped networks (no internet)
- Compliance with strict data residency

### Security Model
- All processing happens on-device
- No data leaves the machine
- Encrypted at-rest storage
- No update checks or phone-home

### Key Commands
- `deadend scan --target <host> --offline`
- `deadend analyze --file <local-report>`
- `deadend export --format pdf --encrypt --recipient <gpg-key>`

---

## HackingBuddyGPT (Experimental)
**Category:** Research & Benchmarks  
**Score:** 43/100

### Capabilities
- Academic benchmark suite for AI pentest capabilities
- Privacy-preserving federated learning for security models
- Novel technique research and validation
- Comparison framework (AI vs human pentester)
- Dataset generation for security training

### When to Use
- Researching new AI pentest methodologies
- Benchmarking LLM security capabilities
- Publishing academic papers
- Developing novel AI-driven attacks

### Benchmarks
- **CVE-Exploit:** Can the AI exploit known CVEs?
- **CTF-Solve:** Capture-the-flag challenge success rate
- **Recon-Quality:** Completeness of attack surface mapping
- **Report-Accuracy**: False positive/negative rates

### Key Commands
- `hackingbuddy benchmark run --suite <suite-name>`
- `hackingbuddy research --topic <topic>`
- `hackingbuddy compare --ai <model> --baseline human`

---

## HexStrike-AI (Experimental)
**Category:** MCP Orchestrator  
**Score:** 41/100

### Capabilities
- Large-scale MCP tool server orchestration
- Dynamic tool discovery and registration
- Parallel execution across multiple tools
- Result aggregation and deduplication
- High-throughput scanning

### When to Use
- Large enterprise environments
- Need to coordinate 10+ security tools
- High-velocity continuous scanning
- Custom tool integration at scale

### ⚠️ Risk Warning
- **High capability = high risk**
- Can trigger many actions quickly
- Strict scope enforcement mandatory
- Always use with `--dry-run` first

### Key Commands
- `hexstrike orchestrate --plan <plan.yaml>`
- `hexstrike mcp discover --registry <url>`
- `hexstrike run --parallel --max-concurrency 10`

---

## PentAGI (Experimental)
**Category:** Autonomous Agent  
**Score:** 38/100

### Capabilities
- Autonomous attack chain generation
- Novel exploitation path discovery
- Self-directed reconnaissance
- Adaptive strategy based on findings

### When to Use
- Exploratory research
- Novel target environments
- Red team exercises with unknown terrain
- Generating new attack hypotheses

### ⚠️ Limitations
- **Limited validation** — outputs must be human-verified
- May suggest impractical or out-of-scope attacks
- Requires oversight and filtering
- Not for production unattended operation

### Key Commands
- `pentagi explore --target <scope>`
- `pentagi generate-chain --objective <goal>`
- `pentagi review --plan <autogen-plan>`

---

## PentestMCP (Experimental)
**Category:** MCP Tool Server  
**Score:** 37/100

### Capabilities
- Exposes security tools via MCP protocol
- Standardized interface for tool integration
- No agent logic — pure tool abstraction
- Composable with orchestrators (HexStrike-AI, PentestAgent)

### When to Use
- Building custom tool integrations
- Standardizing tool interfaces in your team
- Creating MCP-compatible security toolchains
- Infrastructure component (not standalone)

### MCP Server Example
```python
# Example: Nmap MCP server implementation
from mcp.server import Server

server = Server("nmap-mcp")

@server.tool()
async def nmap_scan(target: str, ports: str = "top-1000") -> dict:
    """Run nmap scan against target"""
    # Implementation
    pass
```

### Key Commands
- `pentestmcp serve --tool <tool-name> --port <port>`
- `pentestmcp register --orchestrator <url>`

---

## Tool Selection Decision Tree

```
Need continuous validation?
├── YES → Strix
└── NO → Need AI analysis?
    ├── YES → Local/offline required?
    │   ├── YES → Deadend-CLI
    │   └── NO → Resource-constrained?
    │       ├── YES → Nebel
    │       └── NO → Docker preferred?
    │           ├── YES → PentestGPT
    │           └── NO → Multi-agent needed?
    │               ├── YES → CAI
    │               └── NO → Research/benchmark?
    │                   ├── YES → HackingBuddyGPT
    │                   └── NO → Autonomous exploration?
    │                       ├── YES → PentAGI (with oversight)
    │                       └── NO → PentestGPT (default)
    └── NO → Need orchestration?
        ├── YES → Large scale?
        │   ├── YES → HexStrike-AI
        │   └── NO → PentestAgent (playbooks)
        └── NO → Standard tools (nmap, nuclei, etc.)
```
