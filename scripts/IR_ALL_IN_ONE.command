#!/bin/zsh
# Single launch: pinned CI test/build -> verified download -> backup -> flash -> receipt.
set -euo pipefail
REPO="mokumaisancho/esp32c3-ir-remote"
BRANCH="fix/rmt-idf-error-diagnostics"
cd "${0:A:h}/.."
command -v gh >/dev/null || { print -u2 "BLOCKED: gh missing"; exit 2; }
# Auth errors must not be hidden: keyring, host, PATH and shell environment differ.
# Remove inherited token overrides only for this gh invocation.
auth_output="$(env -u GH_TOKEN -u GITHUB_TOKEN -u GHE_TOKEN gh auth status 2>&1)" || {
  print -u2 "BLOCKED: gh authentication check failed (actual CLI output):"
  print -u2 -- "$auth_output"
  print -u2 "GH_CONFIG_DIR=${GH_CONFIG_DIR:-<default>} GH_HOST=${GH_HOST:-<default>}"
  print -u2 "GH_BINARY=$(command -v gh)"
  exit 2
}
[[ "$(uname -s)" == Darwin ]] || { print -u2 "BLOCKED: requires Mac"; exit 2; }

# Refresh branch before doing anything destructive. Abort on local divergence.
[[ -z "$(git status --porcelain)" ]] || { print -u2 "BLOCKED: dirty local checkout; existing changes preserved"; exit 2; }
git fetch origin "$BRANCH" || exit 2
git checkout "$BRANCH" 2>/dev/null || git checkout -b "$BRANCH" "origin/$BRANCH" || exit 2
git merge --ff-only "origin/$BRANCH" || { print -u2 "BLOCKED: diverged branch; existing changes preserved"; exit 2; }
SHA="$(git rev-parse HEAD)"
[[ -n "$SHA" ]] || exit 2
LOGDIR="$HOME/Library/Logs/esp32c3-ir-remote"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/one-shot-$(date +%Y%m%dT%H%M%S).log"
RECEIPT="$(mktemp /tmp/ir-receipt.XXXXXX)"
job_result="BLOCKED"
run_id=""
report() {
  code=$?
  {
    print "## ESP32-C3 one-shot local receipt"
    print "Source commit: \`$SHA\`"
    print "CI run: \`$run_id\`"
    print "Result: \`$job_result\` (exit \`$code\`)"
    print "Local log: \`$LOG\`"
    print "Last diagnostic lines (redacted):"
    print '~~~'
    if [[ -f "$LOG" ]]; then
      tail -n 35 "$LOG" | sed -E 's/([Pp]assword|[Tt]oken|[Ss]ecret|[Kk]ey)=([^[:space:]]+)/\\1=[REDACTED]/g'
    fi
    print '~~~'
  } > "$RECEIPT"
  gh issue comment 1 -R "$REPO" --body-file "$RECEIPT" >/dev/null 2>&1 || print -u2 "WARN: GitHub receipt upload failed: $RECEIPT"
  if (( code != 0 )); then print -u2 "BLOCKED; detailed log: $LOG"; fi
}
trap report EXIT
exec > >(tee "$LOG") 2>&1
print "Source branch=$BRANCH commit=$SHA"
print "Waiting for matching GitHub CI build (timeout 12 minutes)."
# Workflow push trigger normally starts automatically; dispatch if it has not.
for i in {1..72}; do
  run_id="$(gh run list -R "$REPO" --workflow build.yml --branch "$BRANCH" --commit "$SHA" --limit 1 --json databaseId --jq '.[0].databaseId // empty' 2>/dev/null || true)"
  if [[ -n "$run_id" ]]; then break; fi
  if (( i == 3 )); then gh workflow run build.yml -R "$REPO" --ref "$BRANCH" || true; fi
  sleep 10
done
[[ -n "$run_id" ]] || { print -u2 "BLOCKED: no CI run for source SHA"; exit 2; }
print "Matching CI run=$run_id"
for i in {1..72}; do
  details="$(gh run view "$run_id" -R "$REPO" --json status,conclusion,headSha --jq '[.status,.conclusion,.headSha] | @tsv')" || exit 2
  state="$(gh run view "$run_id" -R "$REPO" --json status --jq .status)"
  conclusion="$(gh run view "$run_id" -R "$REPO" --json conclusion --jq .conclusion)"
  headsha="$(gh run view "$run_id" -R "$REPO" --json headSha --jq .headSha)"
  [[ "$headsha" == "$SHA" ]] || { print -u2 "BLOCKED: CI source mismatch"; exit 2; }
  if [[ "$state" == "completed" ]]; then
    [[ "$conclusion" == "success" ]] || { print -u2 "BLOCKED: CI did not pass ($conclusion)"; exit 2; }
    break
  fi
  sleep 10
done
[[ "$state" == "completed" && "$conclusion" == "success" ]] || { print -u2 "BLOCKED: CI timeout"; exit 2; }
print "CI PASS; backup and flash will run only after artifact hash and chip checks."
export IR_RUN_ID="$run_id" IR_SOURCE_SHA="$SHA"
zsh scripts/flash_mac.command
job_result="FLASH_WRITTEN_NOT_E2E_VERIFIED"
print "Firmware flashed. IR reception and STA HTTP end-to-end tests require live device interaction."
