# AI Prompt Templates for Pentest/Redteam

Ready-to-use prompt templates for PentestGPT, Nebel, and other LLM tools.

## Table of Contents
1. [Reconnaissance Prompts](#reconnaissance-prompts)
2. [Vulnerability Analysis Prompts](#vulnerability-analysis-prompts)
3. [Exploitation Prompts](#exploitation-prompts)
4. [Post-Exploitation Prompts](#post-exploitation-prompts)
5. [Reporting Prompts](#reporting-prompts)
6. [Social Engineering Prompts](#social-engineering-prompts)
7. [AI-Security Specific Prompts](#ai-security-specific-prompts)

---

## Reconnaissance Prompts

### Attack Surface Analysis
```
Analyze the following reconnaissance data and identify the attack surface.
For each finding, rate criticality (Critical/High/Medium/Low) and suggest 
next reconnaissance steps.

[RECON DATA]
{recon_output}

Format output as:
1. Summary (3 bullet points)
2. Attack Surface Map (table: Service | Port | Version | Risk | Next Step)
3. Recommended Priority Targets
```

### Subdomain Evaluation
```
I have the following subdomains for {target_domain}. 
Identify which are most interesting for bug bounty / pentest:

[SUBDOMAINS]
{subdomain_list}

Rank by:
- Likelihood of containing sensitive functionality
- Technology stack diversity
- Dev/staging environment indicators
- Third-party service integration points

Output: Top 10 prioritized with reasoning.
```

### Technology Stack Risk Assessment
```
Based on the following technology fingerprinting results, identify:
1. Known vulnerable components (CVE check)
2. Configuration weaknesses by technology
3. Technology-specific attack vectors
4. Recommended tools for next phase

[FINGERPRINT DATA]
{fingerprint_output}
```

---

## Vulnerability Analysis Prompts

### Vulnerability Prioritization
```
You are a senior penetration tester. Analyze these vulnerability scan 
results and prioritize them for exploitation.

[SCAN RESULTS]
{scan_output}

For each vulnerability, provide:
- Real exploitability (Yes/No/Maybe) with justification
- Exploitation complexity (Low/Medium/High)
- Potential business impact
- Suggested exploitation approach
- Whether it's a false positive risk

Sort by: Exploitability desc, then Impact desc.
```

### CVE to Exploit Mapping
```
Target is running {software} version {version}.
Identify relevant CVEs and map to available exploits.

Output format:
| CVE | CVSS | Exploit Available | Exploit Type | Reliability | Notes |

For each with exploit available, provide:
- Metasploit module name (if exists)
- Manual exploitation steps
- Prerequisites and constraints
```

### Web App Vulnerability Deep-Dive
```
Analyze this HTTP request/response pair for security vulnerabilities.
Provide:
1. Vulnerability name and CWE classification
2. Evidence from the request/response
3. Exploitation scenario (step-by-step)
4. Risk rating with business context
5. Remediation recommendation
6. References (OWASP, CWE, CVE if applicable)

[REQUEST]
{http_request}

[RESPONSE]
{http_response}
```

---

## Exploitation Prompts

### Exploit Chain Generation
```
Given the following findings, construct an exploitation chain to 
achieve {objective}.

[FINDINGS]
{findings_list}

Requirements:
1. Step-by-step exploitation path
2. Alternative paths if primary fails
3. Tools/commands for each step
4. Expected output at each stage
5. Cleanup steps to minimize detection
6. Evidence to capture for reporting

Assume: {assumptions}
Constraints: {constraints}
```

### Privilege Escalation Path
```
I'm on a {os_type} system with the following context:
- Current user: {username}
- Groups: {groups}
- Sudo privileges: {sudo -l output}
- Running processes: {process_list}
- Kernel: {kernel_version}
- Installed software: {software_list}

Identify privilege escalation vectors:
1. Kernel exploits (match kernel to known CVEs)
2. Sudo misconfigurations
3. SUID binaries
4. Service misconfigurations
5. Writable paths
6. Scheduled tasks/cron jobs

For each vector found, provide:
- Exact command sequence
- Success indicators
- Cleanup requirements
```

### Payload Crafting
```
Generate a {payload_type} payload for {target_platform} that:
- Connects back to {c2_host}:{c2_port}
- Uses {communication_method}
- Has {evasion_requirements}
- Is {size_constraint}

Target context:
- AV/EDR: {av_edr_list}
- Network egress: {egress_restrictions}
- Execution context: {execution_context}

Provide:
1. Complete payload code
2. Compilation/packing instructions if needed
3. Delivery method suggestions
4. Evasion technique explanations
```

---

## Post-Exploitation Prompts

### Persistence Options
```
I'm on a compromised {os_type} system. The engagement has {duration} remaining.
Suggest persistence mechanisms ranked by:
1. Stealth (low detection risk)
2. Reliability (survives reboots/updates)
3. Access level maintained
4. Cleanup difficulty

Context:
- Current privileges: {privilege_level}
- AV/EDR: {defense_tools}
- User behavior: {user_patterns}
- Network position: {network_role}

For each mechanism:
- Setup commands
- Trigger conditions
- Detection risks
- Removal procedure
```

### Lateral Movement Options
```
From this compromised host, identify lateral movement opportunities:

[CURRENT HOST CONTEXT]
IP: {ip}
Domain: {domain}
User sessions: {sessions}
Network connections: {connections}
Cached credentials: {credentials}
Trust relationships: {trusts}

[NETWORK CONTEXT]
Adjacent subnets: {subnets}
Known hosts: {host_list}

Provide:
1. Lateral movement paths (visual tree if possible)
2. Technique per hop (Pass-the-Hash, RDP, SSH, WMI, etc.)
3. Required credentials/permissions
4. Detection risk per path
5. Recommended path (optimal stealth + success)
```

---

## Reporting Prompts

### Executive Summary Generation
```
Generate an executive summary for a {engagement_type} engagement 
on {target_organization}.

[KEY FINDINGS]
{critical_findings}

[METRICS]
- Duration: {duration}
- Systems tested: {system_count}
- Vulnerabilities found: {vuln_count}
- Critical: {critical_count}
- High: {high_count}
- Exploitation success rate: {success_rate}

Requirements:
- Max 1 page
- Non-technical language
- Business risk focus
- Remediation priority
- Strategic recommendations
```

### Technical Finding Write-Up
```
Write a technical finding for the following vulnerability:

[VULNERABILITY DATA]
Name: {vuln_name}
CVSS: {cvss_score}
Affected: {affected_systems}
Evidence: {evidence_screenshots/logs}
Exploitation: {exploit_steps}
Impact: {business_impact}

Format:
### {VULNERABILITY NAME} [{SEVERITY}]

**CWE:** {cwe_id}
**CVSS v3.1:** {cvss_vector}
**Affected Systems:** {list}

#### Description
{technical description}

#### Evidence
{screenshots, logs, commands}

#### Exploitation Steps
{numbered steps}

#### Impact
{business + technical impact}

#### Remediation
{specific, actionable steps}

#### References
{CVE, CWE, vendor advisories}
```

### MITRE ATT&CK Mapping
```
Map the following attack path to MITRE ATT&CK techniques:

[ATTACK PATH]
{step_by_step_narrative}

Output:
| Step | ATT&CK ID | Technique Name | Tactic | Procedure |

Include sub-techniques where applicable.
Verify all technique IDs are current (v14.0+).
```

---

## Social Engineering Prompts

### Phishing Email Generation
```
Generate a phishing email pretext for:
- Target role: {target_role}
- Target industry: {target_industry}
- Pretext scenario: {scenario}
- Desired action: {desired_action}
- Urgency level: {urgency}

Requirements:
- Tone appropriate to industry culture
- Reference real company events/news if possible
- Include subtle urgency without being obvious
- Match typical communication style
- Avoid common phishing giveaways

Output:
- Subject line (3 options)
- Email body
- Call-to-action phrasing
- Follow-up strategy
```

### Pretext Development
```
Develop a pretext for a phone-based social engineering attack:

- Target: {target_info}
- Goal: {desired_outcome}
- Your persona: {caller_identity}
- Organization context: {org_details}

Provide:
1. Persona backstory (name, role, reason for calling)
2. Opening script (30 seconds)
3. Handling objections (3 common scenarios)
4. Escalation path if resisted
5. Success indicators
6. Abort triggers
```

---

## AI-Security Specific Prompts

### ML Model Analysis
```
Analyze the following machine learning training pipeline code for 
security vulnerabilities:

[CODE]
{training_pipeline_code}

Focus on:
1. Data poisoning vulnerabilities
2. Model serialization risks (pickle, joblib)
3. Supply chain attacks (dependencies)
4. Input validation gaps
5. Output manipulation possibilities
6. Infrastructure security

For each finding:
- Vulnerability category
- Attack scenario
- Code location (line numbers)
- Severity
- Fix recommendation
```

### Prompt Injection Test
```
Test the following AI system for prompt injection vulnerabilities:
- System type: {ai_system_type}
- Known system prompt: {system_prompt_if_known}
- Input channel: {user_input_method}

Generate test payloads:
1. Direct injection attempts
2. Indirect injection via data
3. Context manipulation
4. Role-play escalation
5. Encoding/obfuscation bypasses

For each payload:
- Injection vector
- Expected behavior if vulnerable
- Expected behavior if protected
- Detection indicators
```

### Adversarial ML Attack Design
```
Design an adversarial attack against a {model_type} model:
- Task: {model_task}
- Input type: {input_format}
- Threat model: {threat_model}
- Goal: {attack_objective}

Provide:
1. Attack taxonomy (evasion, poisoning, extraction, inversion)
2. Specific attack method
3. Required adversary capabilities
4. Implementation approach
5. Expected impact
6. Mitigation strategies
```

---

## Multi-Tool Orchestration Prompts

### CAI Coordinator Prompt
```
You are the coordinator agent for a multi-agent pentest engagement.
Current status:
- Recon Agent: {status} | Findings: {count}
- Web Agent: {status} | Findings: {count}
- Infra Agent: {status} | Findings: {count}
- Exploit Agent: {status} | Findings: {count}

Tasks:
1. Identify correlation opportunities between agents
2. Assign priority targets based on combined findings
3. Flag conflicts or duplicate work
4. Suggest resource reallocation
5. Update engagement timeline

Output: Action plan with agent assignments and rationale.
```

### Strix Pipeline Configuration
```
Generate a Strix CI/CD security pipeline configuration for:
- Application type: {app_type}
- Deployment platform: {platform}
- Compliance requirements: {compliance_list}
- Scan frequency: {frequency}
- Notification targets: {alert_channels}

Output: Complete pipeline YAML with:
1. Tool selection per stage
2. Failure conditions
3. Reporting triggers
4. Benchmark tracking
```
