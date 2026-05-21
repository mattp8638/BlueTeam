
The High-Throughput SIEM Ingestion and OCSF Parsing Engine
Here is the granular MVP specification for the High-Throughput SIEM Ingestion & Parser Engine, formatted for a direct hand-off to your AI coding assistant. Per your instructions, all visualization layers, dashboards, and UI configurations are excluded from this phase.
Core Objective
Build an asynchronous, non-blocking telemetry ingestion backbone that normalizes multi-source data to the Open Cybersecurity Schema Framework (OCSF v1.1.0) on-stream and stores it in a low-latency columnar architecture, while compiling detections into native SQL
.
1. Architectural Requirements
To avoid the bottlenecks of traditional inverted-index SIEMs, the AI must build a decoupled, cloud-scale pipeline:
Routing & Ingestion Layer: Deploy lightweight Vector (by Datadog) agents to ingest events across network protocols (Syslog, Event Forwarding, CloudTrail webhooks)
. Vector must decouple the data extraction from the database to prevent pipeline blockages during high Event-Per-Second (EPS) spikes
.
Stream Buffer Topology: Stream the routed logs into a distributed Apache Kafka cluster, partitioning the topics by high-level source type (e.g., logs.network, logs.endpoint)
.
Columnar Storage Engine: Provision ClickHouse as the target analytical database
. The AI must configure a native ClickHouse Kafka Engine table to pipe data directly into the target tables
.
Strict OCSF Schema (DDL): All tables must be strictly typed to OCSF. The AI must configure ClickHouse tables using the MergeTree() engine, partitioned by toYYYYMM(timestamp) and ordered by (metadata_product_vendor, class_id, timestamp)
.
Storage Optimization: Text variables with repetitive states must be defined as LowCardinality(String)
. The AI must apply ZSTD(1) column compression algorithms directly per column to achieve up to a 10:1 storage footprint reduction
.
2. Functional MVP Capabilities
The backend processing engine must include the following headless modules:
Multi-Engine Stream Parser: Build an automated unpacker for standard security formats (JSON, CEF, RFC5424 Syslog)
. It must normalize fields to OCSF tokens on the fly and safely drop any unmapped parameters into a compressible raw_message field for forensic retention
.
Real-Time Sigma Rule Compiler: Instead of a proprietary query language, build a compiler daemon that automatically translates active open-source Sigma Rules (from the SigmaHQ schema) directly into high-performance ClickHouse SQL statements
. This allows for line-rate execution across the moving time window without external rule translation
.
Background Aggregation: Build ClickHouse Materialized Views using the AggregatingMergeTree engine. This will continuously calculate statistical states (like sum and count states) in the background as data drops into the database, preparing the architecture for future instant-load dashboards
.
3. AI Cognitive Integration (Unstructured Parsing)
Traditional regex parsing is brittle; the development AI must integrate local models to handle unknown data structures.
Zero-Shot Dynamic Parser: For proprietary or unrecognized log strings, route a sample stream to a local Small Language Model (SLM), such as an 8B parameter model
. The SLM must parse the unstructured context, identify entities, and automatically generate custom OCSF JSON field extraction rules (e.g., mapping "User admin_sys" to {user_name: "admin_sys"})
.
Execution Guardrails: The SLM tokenizer must deploy strict input token sanitization boundaries. If an adversary deliberately embeds malicious text strings (e.g., lookalike fields in user-agent payloads) to manipulate parsing logic, the system must flag it to prevent Log Injection Exploitations and Indirect Prompt Injections (OWASP LLM01)
.
Training Data Hand-off: Instruct the AI to fine-tune the SLM using the EVTX-ATTACK-SAMPLES repository (for Windows event attack signatures), the SecRepo data warehouse (for raw malware traffic and PCAP profiles), and the Spider Text-to-SQL Dataset
.
--------------------------------------------------------------------------------
4. MVP Exit Requirements (Definition of Done)
Since there is no dashboard in this phase, the SIEM MVP is complete when the following headless backend tests pass:
High-Velocity Routing Test: Vector successfully receives a simulated Syslog stream, routes it into a Kafka topic, and writes it directly to the ClickHouse database without dropping packets.
Schema Normalization Test: The ClickHouse database successfully accepts a raw event, verifies it maps perfectly to the OCSF MergeTree schema, and applies ZSTD(1) compression to the columns.
Sigma Compilation Test: The compiler daemon successfully ingests a raw Sigma rule (e.g., a rule looking for failed admin auth spikes), translates it into a valid ClickHouse SQL SELECT statement, and triggers an internal alert payload when simulated matching data is injected.
AI Zero-Shot Parsing Test: A completely unrecognized proprietary log string is passed into the pipeline. The SLM successfully evaluates it and returns a syntactically correct OCSF JSON mapping output.
Security Guardrail Test: A simulated log containing an engineered prompt injection payload is ingested. The token-validation layer successfully flags the anomalous structure and isolates it without allowing it to execute against the AI's system instructions.