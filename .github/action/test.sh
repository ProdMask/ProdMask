#!/usr/bin/env bash
# Offline tests for action.sh and action.yml: the version lookup, the runner
# checks, the checksum check, the summary rule and the inputs. Nothing here
# touches the network. Run: bash .github/action/test.sh (it prints only
# failures, and exits 1 if there are any)
set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=action.sh
. "$here/action.sh"

n=0
fails=0
check() { # check <name> <want> <got>
	n=$((n + 1))
	if [ "$2" != "$3" ]; then
		fails=$((fails + 1))
		printf 'FAIL %s\n  want: %s\n  got:  %s\n' "$1" "$2" "$3"
	fi
}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- The version lookup, against a canned git ls-remote --tags.
light=1111111111111111111111111111111111111111
annotated=2222222222222222222222222222222222222222
tagobject=3333333333333333333333333333333333333333
shared=4444444444444444444444444444444444444444
printf '%s\trefs/tags/%s\n' \
	"$light" v0.11.0 \
	"$tagobject" v0.12.0 \
	"$annotated" 'v0.12.0^{}' \
	"$shared" v0.13.0-rc.1 \
	"$shared" v0.13.0 >"$tmp/ls-remote"
ls_remote_tags() { cat "$tmp/ls-remote"; }

pin='prodmask action: pin the action to a release tag such as @v0.13.0, or set version'
check "the version input wins over the ref" v0.12.0 "$(resolve_version v0.12.0 v0.11.0)"
check "a version input without its v" v0.12.0 "$(resolve_version 0.12.0 '')"
check "a prerelease version input" v0.13.0-rc.1 "$(resolve_version v0.13.0-rc.1 '')"
check "a release tag as the ref" v0.13.0 "$(resolve_version '' v0.13.0)"
check "a lightweight tag's commit" v0.11.0 "$(resolve_version '' "$light")"
check "an annotated tag's commit, from its peeled line" v0.12.0 "$(resolve_version '' "$annotated")"
check "an annotated tag object isn't a commit" "$pin" "$(resolve_version '' "$tagobject" 2>&1)"
check "a final release beats an rc on the same commit" v0.13.0 "$(resolve_version '' "$shared")"
check "main is refused" "$pin" "$(resolve_version '' main 2>&1)"
check "no ref is refused" "$pin" "$(resolve_version '' '' 2>&1)"
check "a commit with no release tag is refused" "$pin" "$(resolve_version '' 5555555555555555555555555555555555555555 2>&1)"
check "a version input that isn't a release" "prodmask action: the version input isn't a release such as v0.13.0" \
	"$(resolve_version 'v1; rm -rf /' '' 2>&1)"
(resolve_version '' main) >/dev/null 2>&1
check "a refusal exits non-zero" 1 "$?"
ls_remote_tags() { return 128; }
check "an unreachable remote gives the same refusal" "$pin" "$(resolve_version '' "$light" 2>&1)"

# --- The runner checks.
check "Linux X64" "linux amd64" "$(RUNNER_OS=Linux RUNNER_ARCH=X64 platform)"
check "macOS ARM64" "darwin arm64" "$(RUNNER_OS=macOS RUNNER_ARCH=ARM64 platform)"
check "Windows X64" "windows amd64" "$(RUNNER_OS=Windows RUNNER_ARCH=X64 platform)"
check "Windows ARM64" "windows arm64" "$(RUNNER_OS=Windows RUNNER_ARCH=ARM64 platform)"
check "a 32-bit runner is refused" "prodmask action: prodmask is built for X64 and ARM64 runners only" \
	"$(RUNNER_OS=Linux RUNNER_ARCH=X86 platform 2>&1)"
check "Windows on arm64 without 7z stops in fixed words" "prodmask action: prodmask's action doesn't support Windows on arm64 yet" \
	"$(have() { [ "$1" != 7z ]; }; RUNNER_ARCH=ARM64 windows_preflight 2>&1)"
check "Windows on X64 names the missing tools" "prodmask action: this Windows runner lacks a tool the action needs: curl 7z" \
	"$(have() { [ "$1" != 7z ] && [ "$1" != curl ]; }; RUNNER_ARCH=X64 windows_preflight 2>&1)"
check "Windows with every tool passes" "" "$(have() { true; }; RUNNER_ARCH=ARM64 windows_preflight 2>&1)"

# --- The checksum check.
mkdir "$tmp/dl"
archive=prodmask_9.9.9_linux_amd64.tar.gz
printf 'stand-in archive\n' >"$tmp/dl/$archive"
(
	cd "$tmp/dl" || exit 1
	sum=$( (sha256sum "$archive" 2>/dev/null || shasum -a 256 "$archive") | cut -d' ' -f1)
	printf '%s  %s\n%s  %s\n' "$sum" "$archive" "$sum" prodmask_9.9.9_linux_arm64.tar.gz >checksums.txt
)
(cd "$tmp/dl" && verify_archive "$archive") >/dev/null 2>&1
check "a matching archive passes" 0 "$?"
check "an archive with no line fails" "prodmask action: checksums.txt has no line for prodmask_9.9.9_darwin_amd64.tar.gz" \
	"$(cd "$tmp/dl" && verify_archive prodmask_9.9.9_darwin_amd64.tar.gz 2>&1)"
printf 'tampered\n' >>"$tmp/dl/$archive"
check "a changed archive fails and isn't run" "prodmask action: $archive doesn't match checksums.txt, so it wasn't run" \
	"$(cd "$tmp/dl" && verify_archive "$archive" 2>&1)"

# --- The summary rule. jq is a stand-in here, so the rule is tested without
# the network or a real jq; the real jq is tested below where there is one.
private_for() { # private_for <answer, or "error"> <what jq prints, or "nojq">
	(
		answer=$1
		jqout=$2
		if [ "$answer" = error ]; then fetch_repo_json() { return 22; }; else fetch_repo_json() { printf '%s' "$answer"; }; fi
		if [ "$jqout" = nojq ]; then
			have() { [ "$1" != jq ] && command -v "$1" >/dev/null 2>&1; }
		else
			have() { true; }
			jq() { printf '%s\n' "$jqout"; }
		fi
		repo_private
	)
}
check "private: true writes a summary" true "$(private_for '{"private":true}' true)"
check "private: false writes none" false "$(private_for '{"private":false}' false)"
check "a 404 writes none" false "$(private_for error true)"
check "jq's CRLF on Windows still reads as true" true "$(private_for '{"private":true}' $'true\r')"
check "a connection failure writes none" false "$(fetch_repo_json() { return 7; }; have() { true; }; jq() { echo true; }; repo_private)"
check "an empty answer writes none" false "$(private_for '' '')"
check "a missing field writes none" false "$(private_for '{}' null)"
check "no jq writes none" false "$(private_for '{"private":true}' nojq)"
if command -v jq >/dev/null 2>&1; then
	check "a fork's parent.private is ignored" false \
		"$(fetch_repo_json() { printf '%s' '{"parent":{"private":true},"private":false}'; }; repo_private)"
	check "the real jq reads private: true" true \
		"$(fetch_repo_json() { printf '%s' '{"name":"x","private":true}'; }; repo_private)"
fi
(
	curl() {
		printf '%s\n' "$@" >"$tmp/curl-args"
		cat >"$tmp/curl-stdin"
		printf '%s' '{"private":true}'
	}
	PM_TOKEN=tok-canary-31 GITHUB_API_URL=https://api.example.test GITHUB_REPOSITORY=o/r fetch_repo_json >"$tmp/curl-out"
)
check "the token never reaches curl's command line" "" "$(grep tok-canary "$tmp/curl-args")"
check "the token reaches curl on stdin" "Authorization: Bearer tok-canary-31" "$(cat "$tmp/curl-stdin")"
check "curl reads its headers from stdin" yes "$(grep -qx -- '@-' "$tmp/curl-args" && echo yes || echo no)"
check "the API's URL is the repository's" "https://api.example.test/repos/o/r" "$(tail -n 1 "$tmp/curl-args")"
(
	curl() { cat >"$tmp/curl-stdin"; }
	PM_TOKEN='' fetch_repo_json
)
check "no token sends no Authorization header" "" "$(cat "$tmp/curl-stdin")"
want_summary true false && r=yes || r=no
check "summary: true forces one" yes "$r"
want_summary false true && r=yes || r=no
check "summary: false never writes one" no "$r"
want_summary auto true && r=yes || r=no
check "summary: auto in a private repository" yes "$r"
want_summary auto false && r=yes || r=no
check "summary: auto in a public repository" no "$r"
want_summary auto "" && r=yes || r=no
check "summary: auto when the check didn't run" no "$r"

# --- The summary's size limit.
GITHUB_STEP_SUMMARY="$tmp/small-summary"
printf '# Report\n\nOne line.\n' >"$tmp/small.md"
write_summary "$tmp/small.md"
check "a small report is written whole" "$(cat "$tmp/small.md")" "$(cat "$tmp/small-summary")"
GITHUB_STEP_SUMMARY="$tmp/big-summary"
awk 'BEGIN { for (i = 1; i <= 30000; i++) printf "| row %05d | a table line long enough to fill a megabyte quickly |\n", i }' >"$tmp/big.md"
write_summary "$tmp/big.md"
size=$(wc -c <"$tmp/big-summary" | tr -d ' ')
[ "$size" -le 1048576 ] && r=yes || r=no
check "a big report is cut under 1 MiB ($size bytes)" yes "$r"
tail -n 1 "$tmp/big-summary" | grep -q '^\*The report was cut here' && r=yes || r=no
check "the cut ends with the fixed note" yes "$r"
kept=$(grep -c '^| row ' "$tmp/big-summary")
head -n "$kept" "$tmp/big.md" | cmp -s - <(grep '^| row ' "$tmp/big-summary") && r=yes || r=no
check "the cut falls between whole lines" yes "$r"

# --- The scan step, run as the action runs it, with a stand-in prodmask that
# records its arguments, writes a report and exits as told.
cat >"$tmp/fake-prodmask" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$FAKE_ARGS"
env >"$FAKE_ENV"
while [ $# -gt 0 ]; do [ "$1" = --out ] && out=$2; shift; done
printf '# prodmask scan\n\nWhat staging could do to real people\n' >"$out"
echo "the report, on standard output"
echo "Report written." >&2
exit "$FAKE_EXIT"
EOF
chmod +x "$tmp/fake-prodmask"
run_scan() { # run_scan <exit> <summary>; prints the step's log
	rm -f "$tmp/gh-out" "$tmp/gh-summary"
	(
		cd "$tmp" || exit 1
		FAKE_ARGS="$tmp/args" FAKE_ENV="$tmp/env" FAKE_EXIT=$1 PM_BIN="$tmp/fake-prodmask" \
			PRODMASK_DSN='mysql://ci@db.internal:3306/shop' PRODMASK_PASSWORD='canary-pw-7Qx' \
			PM_SUMMARY=$2 PM_PRIVATE=false PM_REPORT="$tmp/reports/report.md" \
			GITHUB_OUTPUT="$tmp/gh-out" GITHUB_STEP_SUMMARY="$tmp/gh-summary" \
			bash "$here/action.sh" scan 2>&1
	)
}
log=$(run_scan 3 true)
check "a scan that finds something fails the step with 3" 3 "$?"
check "only the scan's stderr reaches the log" "Report written." "$log"
check "exit-code is 3" "exit-code=3" "$(grep '^exit-code=' "$tmp/gh-out")"
check "summary-written is true" "summary-written=true" "$(grep '^summary-written=' "$tmp/gh-out")"
check "the summary holds the report, written before the step failed" "$(cat "$tmp/reports/report.md")" "$(cat "$tmp/gh-summary")"
check "the DSN and password never reach the command line" "" "$(grep -e mysql: -e canary-pw "$tmp/args")"
check "the DSN reaches prodmask in its environment" "PRODMASK_DSN=mysql://ci@db.internal:3306/shop" "$(grep '^PRODMASK_DSN=' "$tmp/env")"
check "the token never reaches prodmask" "" "$(grep '^PM_TOKEN=' "$tmp/env")"
run_scan 0 auto >/dev/null
check "a clean scan passes" "exit-code=0" "$(grep '^exit-code=' "$tmp/gh-out")"
check "summary: auto in a public repository writes none" "summary-written=false" "$(grep '^summary-written=' "$tmp/gh-out")"
check "no summary file is touched" no "$([ -e "$tmp/gh-summary" ] && echo yes || echo no)"
check "a bad summary value is refused" "prodmask action: summary is auto, true or false" "$(run_scan 0 maybe)"

# --- action.yml: every input used is declared, and no expression sits in a
# run line, where a value could become script text.
declared=$(awk '/^inputs:/ { f = 1; next } /^[a-z]/ { f = 0 } f && /^  [a-z-]+:$/ { sub(/:$/, ""); sub(/^ +/, ""); print }' "$root/action.yml")
for used in $(grep -o 'inputs\.[a-z-]*' "$root/action.yml" | sed 's/^inputs\.//' | sort -u); do
	printf '%s\n' "$declared" | grep -qx "$used" && r=yes || r=no
	check "input $used is declared" yes "$r"
done
check "inputs are declared" "dsn password fail-on preset report summary version" "$(printf '%s\n' "$declared" | tr '\n' ' ' | sed 's/ $//')"
check "no expression in a run line" "" "$(grep -n 'run:.*\${{' "$root/action.yml")"
check "every run line is one line" "" "$(grep -n 'run: *[|>]' "$root/action.yml")"

# Silent when everything passes, like gofmt -l.
if [ "$fails" -ne 0 ]; then
	echo "$fails of $n checks failed"
	exit 1
fi
