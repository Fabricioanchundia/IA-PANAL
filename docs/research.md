# Research (Phase 1)

## Honeypot: Cowrie
- Medium-interaction SSH/Telnet honeypot: fake shell, commands never run on a real OS.
- Actively maintained: v3.1.4 released 2026-10-26, frequent releases, Python >= 3.11.
- Logs every session as JSON (IPs, credentials tried, commands, download URLs).

## Cloud: AWS Free plan
- New accounts: up to US$200 in credits for 6 months, no charges on the Free plan.
- Cowrie on a t3.micro is a common, documented setup.
- Main risk is outbound abuse (the honeypot attacking others), which leads to abuse
  reports and account suspension. Mitigation: strict egress firewall, no malware execution.
- To verify before deploying: AWS Acceptable Use Policy (aws.amazon.com/aup).

## Similar projects
| Project | What it does | Gap |
|---|---|---|
| nisargant/AI-Powered-SOC-Analyst-Agent | Ollama + MITRE ATT&CK + incident reports on auth logs | No live honeypot data |
| rows-w1z4rd/agentic-soc-analyst | Multi-agent LangGraph, Qwen 2.5 7B, RAG over ATT&CK | No public evaluation on real attacks |
| tahosprojects/Honeypot-TI-LLM-Splunk | T-Pot + Splunk + LLM MITRE enrichment | No accuracy metrics, no prompt injection tests |
| Andenga/LLM-Assisted-SOC-Alert-Triage | Sigma + ATT&CK triage with precision/recall | Not honeypot-based |

## What makes Panal different
1. Real attacks captured by its own isolated honeypot.
2. Rigorous evaluation: 100+ manually labeled sessions, local model vs API, hallucination rate.
3. Proven resistance to prompt injection hidden in attacker commands.
4. Detects attackers who try to manipulate AI analysts.
5. $0 infrastructure as code, rebuilt with one command, public aggregated map.
