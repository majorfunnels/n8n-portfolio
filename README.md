# n8n AI Automation Workflows

[![Scripts: MIT](https://img.shields.io/badge/Scripts-MIT-yellow.svg)](LICENSE)
[![Workflows: Proprietary](https://img.shields.io/badge/Workflows-Proprietary-red.svg)](workflows/LICENSE)

> Production-grade n8n automation workflows demonstrating AI agent orchestration, multi-stage data pipelines, and intelligent content generation systems.

## 🎯 Overview

This repository showcases enterprise-scale automation systems built with n8n, featuring:

- **AI Agent Orchestration** — Multi-step LLM workflows with structured outputs and validation
- **Data Pipeline Architecture** — Robust ETL patterns with idempotent operations and error recovery
- **API Integration** — Clean data contracts between external services (Airtable, YouTube API, Google Drive)
- **Prompt Engineering** — Production-tested prompts with schema enforcement and hallucination reduction

## 📁 Repository Structure

```
├── workflows/
│   └── sanitized/           # Production workflows (safe for public viewing)
├── docs/
│   ├── architecture/        # System design documentation
│   └── screenshots/         # Annotated workflow visuals
├── scripts/
│   ├── n8n_sanitize.py      # Credential sanitization script
│   ├── n8n_sanitize_batch.py
│   └── pre-commit-hook.py   # Git hook for credential detection
└── README.md
```

## 🔧 Featured Workflows

### Affiliate Arbitrage System (AAS)

A 4-stage automated content pipeline that identifies high-opportunity content gaps and generates multi-format content:

| Stage | Workflow | Purpose |
|-------|----------|---------|
| **AAS-1** | Discovery & Strategy | Identifies "Traffic Leaks" — YouTube videos from smaller channels that significantly outperform their subscriber count, indicating untapped affiliate marketing opportunities |
| **AAS-2** | Copy Pipeline | Generates SEO-optimized long-form content with affiliate integration |
| **AAS-3** | Social Pipeline | Creates platform-specific social media content (Twitter threads, LinkedIn posts) |
| **AAS-4** | Image Generation | Produces branded visual assets with AI image generation |

**Technical Highlights:**

- **Axis-Aware Scoring** — Recognizes when PAIN searches discover PROTOCOL videos (suffering audiences finding trusted solutions)
- **Additive Weighted Formula** — Avoids multiplicative scoring pitfalls where features cancel each other out
- **Round-Robin Distribution** — Content distributed across 5 brand outlets with 90 category rotation
- **Airtable Coordination** — Status-based workflow handoffs with safe re-run capability
- **Fixture Nodes** — Cost-efficient testing without API consumption

### Utility Workflows

| Workflow | Description |
|----------|-------------|
| **Gmail Batch Cleaner** | Intelligent email categorization and bulk cleanup operations |
| **Personal Gmail Assistant** | AI-powered email triage and response drafting |

## 💡 Technical Patterns Demonstrated

| Pattern | Implementation |
|---------|----------------|
| **Idempotent Upserts** | Composite unique keys (`{run_id}_{video_id}`) for safe re-runs |
| **Schema Validation** | Structured JSON outputs with strict type enforcement |
| **Error Boundaries** | Graceful degradation with Airtable status tracking |
| **Token Optimization** | Minimal context passing, canonical field flow |
| **Rate Limit Management** | Split-in-batches patterns for external APIs |
| **Data Contracts** | Snake_case internal processing → human-readable Airtable fields |

## 🛠️ Tech Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                        AAS Pipeline                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │  AAS-1   │───▶│  AAS-2   │───▶│  AAS-3   │───▶│  AAS-4   │  │
│  │Discovery │    │   Copy   │    │  Social  │    │  Images  │  │
│  └────┬─────┘    └────┬─────┘    └────┬─────┘    └────┬─────┘  │
│       │               │               │               │         │
│       ▼               ▼               ▼               ▼         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Airtable Hub                          │   │
│  │  (Traffic Leaks • Videos • Channels • Copy • Images)    │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

| Layer | Technology |
|-------|------------|
| **Orchestration** | n8n (self-hosted) |
| **Database** | Airtable (relational coordination layer) |
| **AI Models** | OpenRouter → Claude Sonnet 4 |
| **Research** | Perplexity API |
| **Data Sources** | YouTube Data API v3 |
| **Storage** | Google Drive (programmatic organization) |
| **Image Gen** | OpenRouter → Gemini 2.5 Flash |

## 🔐 Security Notes

All workflows have been sanitized using custom Python scripts that:

- ✅ Remove credential IDs and references
- ✅ Redact webhook URLs and paths
- ✅ Replace Airtable base/table IDs with placeholders
- ✅ Clear Google Drive folder identifiers
- ✅ Strip API keys from inline configurations
- ✅ Redact AI prompts (IP protection)
- ✅ Clear test fixture data

**These workflows are safe to import** but require your own credentials to be configured.

## 🚀 Usage

### Importing Workflows

1. Download the desired `.json` file from `workflows/sanitized/`
2. In n8n: **Workflows** → **Import from File**
3. Configure your own credentials for each service
4. Update Airtable base/table IDs to match your schema

### Running the Sanitization Scripts

```bash
# Single file
python scripts/n8n_sanitize.py input.json output.json --report

# With prompt redaction (protects IP)
python scripts/n8n_sanitize.py input.json output.json --redact-prompts

# Batch processing
python scripts/n8n_sanitize_batch.py ./raw ./sanitized --redact-prompts
```

### Installing the Pre-Commit Hook

```bash
cp scripts/pre-commit-hook.py .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## 📬 Contact

- **LinkedIn:** https://www.linkedin.com/in/jcmarx/
- **Email:** majorfunnels@gmail.com

## 📄 License

This repository uses dual licensing:

| Directory | License | What it means |
|-----------|---------|---------------|
| `/scripts/` | MIT | Use freely, attribution appreciated |
| `/docs/` | MIT | Use freely, attribution appreciated |
| `/workflows/` | All Rights Reserved | View & learn only, no copying or commercial use |

See [LICENSE](LICENSE) for scripts and [workflows/LICENSE](workflows/LICENSE) for workflow terms.

---

*Built with n8n, Claude, and iterative refinement.*
