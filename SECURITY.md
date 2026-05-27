# BlueTeam Platform Security Policy

This document outlines the security boundaries, cryptographic integrations, and AI guardrails built into the BlueTeam Cybersecurity Operations Platform.

## 1. AI Security & Guardrails (OWASP LLM01)

The platform heavily utilizes local Hugging Face AI models for anomaly detection and Root Cause Analysis (RCA). AI models are highly susceptible to **Indirect Prompt Injection** (where an attacker places malicious instructions inside a log file, hoping the AI reads it and executes it).

*   **Sanitization Layer:** The `AIReportingEngine` implements a strict sanitization layer before any log is passed to the text-generation pipelines. It uses regex pattern matching to strip known adversarial prompts (e.g., `"ignore previous instructions"`, `"bypass guardrail"`, `"drop all tables"`).
*   **Isolation:** The AI models run directly in the Python memory space without external API permissions. They return JSON or text strings. They **do not** have direct execution authority over the SOAR DAG runner.

## 2. Cryptographic Ledger (Chain of Custody)

In order for logs and forensic evidence to be legally admissible, their integrity must be mathematically guaranteed.

*   **Merkle Hash Chain:** The `MerkleLedger` in `src/ir_core` utilizes a cryptographic append-only transaction ledger.
*   Every transaction computes its hash as: `H(T_n) = SHA-256(T_n || H(T_n-1))`
*   If an attacker breaches the backend and attempts to alter a log or incident ticket, the final `verify_integrity()` check will mathematically fail, exposing the tampering.

## 3. Best Practices for Production Deployment

While this repository provides a full end-to-end simulation, scaling to a true production environment requires hardening the infrastructure:

*   **WebSockets over TLS:** The Nerve Center API (`/ws/fleet`) uses unencrypted WebSockets (`ws://`) for local development. In production, this must be wrapped in a reverse proxy (like Nginx or Traefik) and upgraded to Secure WebSockets (`wss://`).
*   **Message Broker (Kafka/RabbitMQ):** Do not expose the FastAPI backend directly to the public internet for agent telemetry. Deploy a Message Broker (e.g., Apache Kafka). Endpoint Agents should authenticate and push telemetry to a Kafka topic. The SIEM should reside in a protected internal subnet, pulling from that topic. This protects the backend from volumetric DDoS attacks.
*   **Role-Based Access Control (RBAC):** The React frontend currently simulates an open dashboard. Implement strict JWT authentication. Only Level-3 Responders should have the authorization token required to execute SOAR isolation playbooks.

## 4. Reporting a Vulnerability

If you discover a vulnerability in the platform code, please open a standard GitHub issue or submit a Pull Request.
