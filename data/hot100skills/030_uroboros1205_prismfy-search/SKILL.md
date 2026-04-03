---
name: prismfy-search
description: >
  Search the web across 10 engines — Google, Reddit, GitHub, arXiv, Hacker News,
  and more — using Prismfy. Use when the user asks to search the web, look something
  up, find recent news, search for code examples, find Reddit discussions, look up
  academic papers, or needs any live information from the internet.
version: 1.0.0
metadata:
  openclaw:
    requires:
      env:
        - PRISMFY_API_KEY
      bins:
        - curl
        - jq
    primaryEnv: PRISMFY_API_KEY
    emoji: "🔍"
    homepage: https://prismfy.io
---

# 🔍 Prismfy Web Search

Real-time web search across **10 engines** — Google, Reddit, GitHub, arXiv,
Hacker News, Ask Ubuntu, and more — powered by [Prismfy](https://prismfy.io).
No proxy hassle, no CAPTCHA, no blocked requests. Just results.

> Get your free API key at [prismfy.io](https://prismfy.io) and you're ready to go.

---

## Setup

### 1. Get an API key

Head to [prismfy.io](https://prismfy.io), create an account, and grab your API key from the dashboard.
There's a free tier — no credit card needed to get started.

---

### 2. Add the key to your environment

Pick the method that fits your setup:

**Option A — Shell profile (works everywhere, permanent)**
```bash
# Add to ~/.zshrc or ~/.bashrc:
export PRISMFY_API_KEY="ss_live_your_key_here"

# Then reload:
source ~/.zshrc   # or: source ~/.bashrc
```

**Option B — Project `.env` file (per-project)**
```bash
# In your project root, create or edit .env:
echo 'PRISMFY_API_KEY=ss_live_your_key_here' >> .env
```
Claude Code automatically loads `.env` files from the project root.

**Option C — Claude Code global env (recommended)**
```bash
# Add to ~/.claude/.env (applies to all Claude Code sessions):
echo 'PRISMFY_API_KEY=ss_live_your_key_here' >> ~/.claude/.env
```

---

### 3. Verify it works

```bash
bash search.sh --quota
```

You should see your plan, searches used, and how many you have left.
If you see `PRISMFY_API_KEY is not set` — check that you reloaded your shell or that the `.env` file is in the right place.

---

That's it. No credit card, no waitlist. 3,000 free searches every month.

---

## How to use

Just ask naturally — the skill handles the rest:

```
/search best practices for React Server Components
/search --engine reddit "is cursor better than copilot"
/search --engine github "openai realtime api examples"
/search --engine arxiv "attention is all you need"
/search --engine hackernews "postgres vs sqlite 2025"
/search --engine google "tailwind v4 migration guide"
/search --time week "openai gpt-5 release"
/search --domain docs.python.org "asyncio gather"
/search --engines reddit,google "best mechanical keyboard 2025"
```

Or just talk normally:
- *"Search Reddit for people's opinions on Bun vs Node"*
- *"Find recent GitHub repos for building MCP servers"*
- *"Look up the arXiv paper on chain-of-thought prompting"*
- *"What are people saying on Hacker News about SQLite?"*

---

## Available engines

| Engine | What it's good for |
|---|---|
| `brave` | General web search, privacy-first |
| `startpage` | Google results without tracking |
| `yahoo` | General web, news |
| `google` | Most comprehensive web search |
| `reddit` | Real user opinions, discussions |
| `github` | Code, repos, issues, READMEs |
| `arxiv` | Academic papers, research |
| `hackernews` | Tech community, startups |
| `askubuntu` | Linux, Ubuntu, shell questions |
| `yahoonews` | Latest news headlines |

**Default** (no `--engine`): uses `brave` + `yahoo` in parallel.

---

## Options

| Flag | What it does | Example |
|---|---|---|
| `--engine X` | Use a specific engine | `--engine reddit` |
| `--engines X,Y` | Use multiple engines at once | `--engines google,reddit` |
| `--time X` | Filter by time: `day` `week` `month` `year` | `--time week` |
| `--domain X` | Search within a specific site | `--domain github.com` |
| `--page N` | Go to results page N | `--page 2` |
| `--quota` | Check your remaining free quota | `--quota` |

---

## What Claude does with results

This skill doesn't just paste a list of links. Claude:

- **Answers your question** using the search results as live context
- **Cites sources** with URLs so you can dig deeper
- **Extracts code** from results when you're looking for examples
- **Summarizes discussions** when searching Reddit or Hacker News
- **Suggests follow-up searches** if the first results aren't quite right

---

## How the skill works

The skill uses `search.sh` — a bundled helper script that handles the API call,
error messages, and result formatting for you:

```bash
# Simple search
bash search.sh "typescript best practices 2025"

# With engine
bash search.sh --engine reddit "is bun worth switching from node"

# Multiple engines
bash search.sh --engines google,reddit "nextjs vs remix"

# With time filter
bash search.sh --time week "openai new model"

# Raw JSON output
bash search.sh --raw "rust async runtime"
```

Results come back with title, URL, snippet, and which engine found it.
**Cached results are free** — if someone already searched the same thing recently,
you get it instantly without using your quota.

---

## Check your quota

```
/search --quota
```

This calls `/v1/user/me` and shows your current plan, searches used,
searches remaining, and when your quota resets.

---

## Troubleshooting

**`PRISMFY_API_KEY is not set`**
→ Add `export PRISMFY_API_KEY="ss_live_..."` to your shell profile and restart the terminal.

**`401 Unauthorized`**
→ Double-check your key starts with `ss_live_`. Keys are shown only once — if lost, create a new one in the Dashboard → API Keys.

**`Engine not available on your plan`**
→ Google, Reddit, GitHub etc. require a paid plan. Free tier supports `brave`, `startpage`, and `yahoo`. Use one of those or upgrade at [prismfy.io](https://prismfy.io).

**No results / empty results**
→ Try a different engine or rephrase your query. The skill will suggest alternatives automatically.

---


## Implementation

When this skill is invoked, follow these steps:

1. **Parse the user's request** — extract the query, engine preference, time filter, domain, and page number.

2. **Run `search.sh`** with the parsed arguments:
```bash
bash search.sh [--engine X] [--engines X,Y] [--time X] [--domain X] [--page N] <query>
```

3. **Handle the output:**
   - `⚡ Cached result` line → mention it was free (no quota used)
   - Empty results → suggest rephrasing or a different engine
   - `❌ Invalid API key` → guide user to check `PRISMFY_API_KEY`
   - `❌ Engine not available` → tell user to check their plan at prismfy.io

4. **Present results** in a clear, useful format:
   - Answer the user's underlying question using the content
   - List sources with titles and URLs
   - For Reddit/HN results: summarize the discussion sentiment
   - For GitHub results: highlight repo name and what it does
   - For arXiv results: summarize the abstract

5. **For `--quota` flag:**
```bash
bash search.sh --quota
```

---

*Powered by [Prismfy](https://prismfy.io) — web search infrastructure for developers.*
