# Panal — Estado del proyecto

Honeypot en la nube + agente analista SOC con IA (cuarto proyecto de portafolio de Fabricio; Ninca, Lupa Pública y Halcón ya terminados).
Repo: https://github.com/Fabricioanchundia/IA-PANAL (público, MIT, .gitignore Python; creado 6 nov 2026). Local: ~/projects/IA-PANAL en WSL, clonado ✅, abre con `cd ~/projects/IA-PANAL && code .` ✅.
Prompt original: el del inicio del chat de Ninca (Cowrie, pipeline, agente SOC + MITRE ATT&CK, Terraform, mapa público, informe de 30 días).
Perfil: el mismo de los otros proyectos (Python 3.12, uv, DuckDB, WSL2 Ubuntu-24.04, Docker, Ollama qwen2.5:7b en RTX 5060, GitHub SSH con passphrase, flujo de PRs). Presupuesto ~$0 (tiene tarjeta, pero no quiere gastar). Usar opción múltiple y respuestas cortas. No insistir con preguntas sin responder: tomar el default y seguir.
Usa Windows Terminal (Ubuntu) o la terminal de VS Code. Claude puede hacer git ls-remote/clone anónimo del repo público para verificar.
Correo universitario: AFANCHUNDIA@pucesm.edu.ec (PUCE Sede Manabí).

## Reglas no negociables
- El honeypot NUNCA expuesto desde la laptop ni la red de casa. En local solo para pruebas en localhost.
- Firewall de salida estricto; no guardar ni ejecutar malware (solo hashes y URLs); nada de hack back.
- Verificar la política de uso aceptable del proveedor antes de desplegar.
- Avisar siempre antes de cualquier paso con costo.
- Nunca subir IDs de cuenta AWS, IPs de admin ni llaves al repo.

## Nube
- Azure: DESCARTADO (sin Azure for Students; la "Suscripción de Azure 1" de la PUCE es de su TESIS FISIOTECH → no mezclar).
- AWS: tiene DOS cuentas.
  - 428411627626 (nombre = fabricioanchundia7@gmail.com): VIEJA, de hace años; según él sin plan y sin tarjeta. Riesgo: sin método de pago probablemente no deja crear EC2; si deja, genera deuda y AWS puede suspender/borrar a mitad de los 30 días.
  - 951510214664 (nombre "Fabrici07820032026"): NUEVA, creada 6 nov con tarjeta, debería ser Free plan; "no deja hacer nada" = probablemente activación pendiente (hasta 24 h). Recomendada para Panal.
  - Decisión final de cuenta: aplazada hasta la Fase 3. Antes: MFA en root + budget.
- Free plan: créditos US$100 + hasta US$100 más, 6 meses; no cobra; al acabarse cierra la cuenta. NUNCA "Upgrade to Paid plan".

## Fase 1 — Investigación (6 nov 2026)
- Cowrie vigente: 3.1.4 (26 oct 2026), releases semanales, Python ≥3.11.
- AWS AUP: no se pudo abrir la página oficial desde el contenedor de Claude. Riesgo real = abuso SALIENTE (reportes de abuso → suspensión). Mitigación: firewall de salida estricto. Pendiente que Fabricio lea aws.amazon.com/aup antes de la Fase 3. Hay muchos tutoriales de Cowrie en EC2 t3.micro.
- Competencia: nisargant/AI-Powered-SOC-Analyst-Agent (Ollama + MITRE + reportes, logs de auth), rows-w1z4rd/agentic-soc-analyst (LangGraph, Qwen 2.5 7B, RAG MITRE), tahosprojects/Honeypot-TI-LLM-Splunk (T-Pot + Claude + MITRE; sin evaluación ni pruebas de prompt injection), Andenga/LLM-Assisted-SOC-Alert-Triage (métricas), beenuar/AiSOC.
- Diferenciadores de Panal: datos reales propios; evaluación con 100+ sesiones etiquetadas (local vs API, alucinaciones); resistencia a prompt injection DEMOSTRADA con pruebas; detectar intentos de prompt injection reales contra analistas IA (conecta con Ninca: hilo AI Security); infra como código reconstruible a $0; mapa público agregado.
- Entregable: docs/research.md vía rama docs/research + PR (contenido enviado en el chat).

## Plan de fases (comprimido porque ya domina el stack)
0. Cuenta en la nube + repo ✅
1. Investigación (en curso)
2. Cowrie en Docker en localhost (prueba controlada)
3. Nube con Terraform + firewall de salida → empieza la recolección de 30 días
4. Pipeline + enriquecimiento (DuckDB)
5. Agente SOC + MITRE ATT&CK (Ollama)
6. Seguridad del agente (prompt injection)
7. Evaluación con 100+ sesiones etiquetadas
8. Sigma, monitoreo Telegram, CI/CD, reconstrucción con un comando
9. Mapa público (GitHub Pages, datos agregados)
10. Informe de 30 días + LinkedIn

## Estado (6 nov 2026, 12:35)
- FASE 0 cerrada. FASE 1: investigación entregada; falta PR de docs/research.md y responder la pregunta del diferenciador.
- Rol objetivo: no respondió → default enfoque equilibrado (SOC + AI Security).