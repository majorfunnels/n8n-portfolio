# AAS Pipeline Architecture

## System Overview

The Affiliate Arbitrage System (AAS) is a 4-stage content automation pipeline that discovers high-opportunity affiliate marketing opportunities and generates multi-format content automatically.

## Core Concept: Traffic Leaks

A "Traffic Leak" is a YouTube video from a smaller channel that significantly outperforms its subscriber count. This indicates:

1. **Untapped demand** — Audiences are actively searching for this content
2. **Weak competition** — Established creators haven't captured this niche
3. **Affiliate opportunity** — Frustrated buyers at decision points

## Pipeline Stages

### Stage 1: Discovery & Strategy (AAS-1)

**Purpose:** Find and score Traffic Leak opportunities

**Process:**
1. Rotate through brand outlets (Health, Wealth, Relationships, Lifestyle, Tech)
2. Select categories based on round-robin schedule
3. Generate search queries via AI
4. Query YouTube API for videos matching criteria
5. Score opportunities using axis-aware algorithm
6. Store qualified leads in Airtable

**Key Innovation:** Axis-aware scoring recognizes that PAIN searches (desperate queries) often discover PROTOCOL videos (trusted solutions). The system rewards this mismatch rather than penalizing solution-oriented content.

### Stage 2: Copy Pipeline (AAS-2)

**Purpose:** Generate long-form SEO content

**Process:**
1. Pull qualified Traffic Leaks from Airtable
2. Research affiliate programs via Perplexity
3. Generate comprehensive blog posts with AI
4. Include affiliate integration points
5. Store copy assets in Airtable

### Stage 3: Social Pipeline (AAS-3)

**Purpose:** Create platform-specific social content

**Process:**
1. Pull copy assets from previous stage
2. Generate Twitter thread versions
3. Generate LinkedIn post versions
4. Generate short-form hooks
5. Store social assets in Airtable

### Stage 4: Image Generation (AAS-4)

**Purpose:** Create branded visual assets

**Process:**
1. Pull content requiring images
2. Generate image prompts based on content
3. Call image generation API
4. Upload to Google Drive (organized by niche)
5. Link assets back to Airtable records

## Data Architecture

### Airtable Schema (Operations HQ)

| Table | Purpose |
|-------|---------|
| **Traffic Leaks** | Central hub linking all assets |
| **Videos** | YouTube video metadata |
| **Channels** | YouTube channel data |
| **Searches** | Query history and results |
| **Runs** | Execution tracking |
| **Copy** | Generated written content |
| **Images** | Generated visual assets |

### Key Design Decisions

1. **Flat field structures** — Canonical context flows through without nesting
2. **Composite unique keys** — `{run_id}_{video_id}` for idempotent upserts
3. **Status-based coordination** — Workflows check status fields rather than direct triggers
4. **Snake_case internally** — Human-readable names only at Airtable boundary

## Scheduling

- **Frequency:** Twice daily (14 runs/week)
- **Rotation:** Round-robin at brand outlet level, then category level
- **Coverage:** Each of 5 outlets runs ~3x/week
- **Category cycle:** ~2 months to rotate through all 90 categories

## Error Handling

- Airtable serves as checkpoint and safety net
- Failed stages can be re-run without duplicate records (idempotent)
- Status fields track pipeline progress
- Fixture nodes enable testing without API costs
