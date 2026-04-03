#!/usr/bin/env bash
# Prismfy Web Search — CLI helper for the prismfy-search skill
# Usage: search.sh [options] <query>
#
# Options:
#   --engine  <engine>         Single engine (brave, google, reddit, github, arxiv, hackernews, askubuntu, startpage, yahoo, yahoonews)
#   --engines <e1,e2,...>      Multiple engines, comma-separated
#   --time    <day|week|month|year>
#   --domain  <example.com>
#   --page    <number>
#   --lang    <en|ru|de|...>
#   --quota                    Show remaining quota instead of searching
#   --raw                      Print raw JSON (skip jq pretty-print)

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────────

BASE_URL="https://api.prismfy.io"
SEARCH_ENDPOINT="$BASE_URL/v1/search"
QUOTA_ENDPOINT="$BASE_URL/v1/user/me"

# ── Helpers ───────────────────────────────────────────────────────────────────

die() { echo "❌  $*" >&2; exit 1; }

check_deps() {
  command -v curl >/dev/null 2>&1 || die "curl is required but not installed."
  command -v jq   >/dev/null 2>&1 || die "jq is required but not installed. Install with: brew install jq / apt install jq"
}

check_key() {
  [[ -z "${PRISMFY_API_KEY:-}" ]] && die "PRISMFY_API_KEY is not set.
Set it in your shell profile:
  export PRISMFY_API_KEY=\"ss_live_your_key_here\"
Get a free key (3,000 searches/month) at: https://prismfy.io/register"
}

# ── Quota ─────────────────────────────────────────────────────────────────────

show_quota() {
  local response
  response=$(curl -sf "$QUOTA_ENDPOINT" \
    -H "Authorization: Bearer $PRISMFY_API_KEY") || \
    die "Failed to reach Prismfy API. Check your internet connection or API key."

  local code
  code=$(echo "$response" | jq -r '.code // empty')
  [[ "$code" == "UNAUTHORIZED" ]] && die "Invalid API key. Check your PRISMFY_API_KEY."

  echo "$response" | jq -r '
    "👤  Plan:       \(.tier | ascii_upcase)",
    "✅  Used:       \(.quota.used) searches",
    "🔢  Remaining:  \(.quota.remaining) searches",
    "📦  Total:      \(.quota.total) searches/month",
    "🔄  Resets at:  \(.quota.expiresAt)"
  '
}

# ── Search ────────────────────────────────────────────────────────────────────

run_search() {
  local query="$1"
  local engines_json="$2"
  local time_range="$3"
  local domain="$4"
  local page="$5"
  local lang="$6"
  local raw="$7"

  # Build JSON body
  local body
  body=$(jq -n \
    --arg q "$query" \
    --argjson engines "$engines_json" \
    --arg lang "$lang" \
    --arg page "$page" \
    '{query: $q, engines: $engines, language: $lang, page: ($page | tonumber)}')

  [[ -n "$time_range" ]] && body=$(echo "$body" | jq --arg t "$time_range" '. + {timeRange: $t}')
  [[ -n "$domain"     ]] && body=$(echo "$body" | jq --arg d "$domain"     '. + {domain: $d}')

  local response
  response=$(curl -sf -X POST "$SEARCH_ENDPOINT" \
    -H "Authorization: Bearer $PRISMFY_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$body") || die "Failed to reach Prismfy API. Check your internet connection."

  # Check for API errors
  local err_code
  err_code=$(echo "$response" | jq -r '.code // empty')
  case "$err_code" in
    UNAUTHORIZED)
      die "Invalid API key. Check your PRISMFY_API_KEY." ;;
    QUOTA_EXCEEDED)
      die "Monthly quota exceeded. Upgrade at https://prismfy.io or wait for reset." ;;
    ENGINE_NOT_AVAILABLE)
      die "One or more engines are not available on your plan.
Free tier engines: brave, startpage, yahoo
Upgrade for Google, Reddit, GitHub, arXiv, etc.: https://prismfy.io" ;;
    "")
      : ;; # no error
    *)
      die "API error ($err_code): $(echo "$response" | jq -r '.message // "unknown error"')" ;;
  esac

  if [[ "$raw" == "true" ]]; then
    echo "$response" | jq .
    return
  fi

  # Pretty print results
  local cached result_count
  cached=$(echo "$response" | jq -r '.cached')
  result_count=$(echo "$response" | jq '.results | length')

  if [[ "$result_count" -eq 0 ]]; then
    echo "🔍  No results found for: \"$query\""
    echo "💡  Try a different engine (--engine google) or rephrase your query."
    exit 0
  fi

  # Cache notice
  [[ "$cached" == "true" ]] && echo "⚡  Cached result (free, no quota deducted)" || true

  # Print each result
  echo ""
  echo "$response" | jq -r '
    .results[] |
    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    "📄  \(.title)",
    "🔗  \(.url)",
    "🔎  [\(.engine)]  \(.content)",
    ""
  '

  # Meta info
  echo "$response" | jq -r '
    if .cached then
      "📊  \(.results | length) results (cached)"
    else
      "📊  \(.results | length) results · \(.meta.durationMs)ms · engines: \(.meta.engines | join(", "))"
    end
  '
}

# ── Argument parsing ──────────────────────────────────────────────────────────

main() {
  check_deps
  check_key

  local engines=""
  local time_range=""
  local domain=""
  local page="1"
  local lang="en"
  local quota_mode="false"
  local raw="false"
  local query_parts=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --engine)
        shift; engines="[\"$1\"]" ;;
      --engines)
        shift
        # Convert "google,reddit" → ["google","reddit"]
        engines=$(echo "$1" | jq -Rc 'split(",")')  ;;
      --time)
        shift; time_range="$1" ;;
      --domain)
        shift; domain="$1" ;;
      --page)
        shift; page="$1" ;;
      --lang)
        shift; lang="$1" ;;
      --quota)
        quota_mode="true" ;;
      --raw)
        raw="true" ;;
      --help|-h)
        sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
        exit 0 ;;
      -*)
        die "Unknown option: $1. Run with --help for usage." ;;
      *)
        query_parts+=("$1") ;;
    esac
    shift
  done

  if [[ "$quota_mode" == "true" ]]; then
    show_quota
    exit 0
  fi

  [[ ${#query_parts[@]} -eq 0 ]] && die "No query provided. Usage: search.sh [options] <your query>"

  local query="${query_parts[*]}"

  # Default engines if none specified
  [[ -z "$engines" ]] && engines='["brave","yahoo"]'

  run_search "$query" "$engines" "$time_range" "$domain" "$page" "$lang" "$raw"
}

main "$@"
