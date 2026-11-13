#!/usr/bin/env bash
# The steps of the prodmask scan action (action.yml at the repository root).
# Every input arrives in an environment variable, never in the script's text.
#
#   action.sh install      find the release, download it, check it against
#                          checksums.txt and unpack it
#   action.sh visibility   ask GitHub whether this repository is private
#   action.sh scan         run the scan, write the report and, if wanted, the
#                          job summary
#
# test.sh, next to it, sources this file and tests the functions offline.

# The releases come from here, whichever repository the action runs from.
PM_REPO="ProdMask/ProdMask"
# GitHub keeps at most 1 MiB of one step's job summary.
PM_SUMMARY_LIMIT=1048576

die() {
	printf 'prodmask action: %s\n' "$*" >&2
	exit 1
}

have() { command -v "$1" >/dev/null 2>&1; }

output() { printf '%s=%s\n' "$1" "$2" >>"${GITHUB_OUTPUT:-/dev/null}"; }

# A release tag, with or without its v: v0.13.0, 0.13.0 or v0.13.0-rc.1.
is_version() { [[ $1 =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; }

ls_remote_tags() { git ls-remote --tags "https://github.com/$PM_REPO.git"; }

# Prints every tag whose commit is $1. An annotated tag's own line names the
# tag object, so its peeled ^{} line gives the commit.
tags_at_commit() {
	ls_remote_tags | awk -v sha="$1" '
		{ ref = $2; sub(/^refs\/tags\//, "", ref)
		  if (ref ~ /\^\{\}$/) { sub(/\^\{\}$/, "", ref); peeled[ref] = $1 } else { plain[ref] = $1 } }
		END {
			for (t in plain) { c = (t in peeled) ? peeled[t] : plain[t]; if (c == sha) print t }
			for (t in peeled) if (!(t in plain) && peeled[t] == sha) print t
		}'
}

# Reads tags on stdin and prints the newest final release, or else the newest
# prerelease.
pick_tag() {
	local tags final
	tags=$(grep -E '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' || true)
	final=$(printf '%s\n' "$tags" | grep -v -e - -e '^$' | newest || true)
	if [ -n "$final" ]; then
		printf '%s\n' "$final"
		return
	fi
	printf '%s\n' "$tags" | grep -e - | newest || true
}

newest() { sed 's/^v//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1 | sed 's/^/v/'; }

# Prints the release tag to install: the version input, else the action's own
# tag, else the release tag on the commit the action is pinned to.
resolve_version() {
	local version="${1:-}" ref="${2:-}" tag
	if [ -n "$version" ]; then
		is_version "$version" || die "the version input isn't a release such as v0.13.0"
		printf 'v%s\n' "${version#v}"
		return
	fi
	if is_version "$ref"; then
		printf 'v%s\n' "${ref#v}"
		return
	fi
	if [[ $ref =~ ^[0-9a-f]{40}$ ]]; then
		tag=$(tags_at_commit "$ref" | pick_tag) || tag=""
		if [ -n "$tag" ]; then
			printf '%s\n' "$tag"
			return
		fi
	fi
	die "pin the action to a release tag such as @v0.13.0, or set version"
}

# Prints the release's names for this runner's system and processor.
platform() {
	local os arch
	case "${RUNNER_OS:-}" in
	Linux) os=linux ;;
	macOS) os=darwin ;;
	Windows) os=windows ;;
	*) die "prodmask is built for Linux, macOS and Windows runners only" ;;
	esac
	case "${RUNNER_ARCH:-}" in
	X64) arch=amd64 ;;
	ARM64) arch=arm64 ;;
	*) die "prodmask is built for X64 and ARM64 runners only" ;;
	esac
	printf '%s %s\n' "$os" "$arch"
}

# On Windows the action runs under Git Bash and needs these tools.
windows_preflight() {
	local missing="" t
	for t in bash curl 7z cygpath; do
		have "$t" || missing="$missing $t"
	done
	[ -z "$missing" ] && return 0
	[ "${RUNNER_ARCH:-}" = ARM64 ] && die "prodmask's action doesn't support Windows on arm64 yet"
	die "this Windows runner lacks a tool the action needs:$missing"
}

runner_temp() {
	if [ -z "${RUNNER_TEMP:-}" ]; then
		mktemp -d
	elif [ "${RUNNER_OS:-}" = Windows ] && have cygpath; then
		cygpath -u "$RUNNER_TEMP"
	else
		printf '%s\n' "$RUNNER_TEMP"
	fi
}

# A path as the runner's own tools write it, for the action's outputs.
native_path() {
	if [ "${RUNNER_OS:-}" = Windows ] && have cygpath; then
		cygpath -w "$1"
	else
		printf '%s\n' "$1"
	fi
}

sha256_check() {
	if have sha256sum; then
		sha256sum -c - >/dev/null 2>&1
	else
		shasum -a 256 -c - >/dev/null 2>&1
	fi
}

# Checks $1, in the current folder, against its line in checksums.txt.
verify_archive() {
	local line
	line=$(grep -E "^[0-9a-f]{64}  ${1//./\\.}\$" checksums.txt || true)
	[ -n "$line" ] && [ "$(printf '%s\n' "$line" | wc -l | tr -d ' ')" = 1 ] ||
		die "checksums.txt has no line for $1"
	printf '%s\n' "$line" | sha256_check || die "$1 doesn't match checksums.txt, so it wasn't run"
}

download() {
	curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1" || die "can't download $1"
}

unpack() {
	case "$1" in
	*.zip) 7z x -y "$1" >/dev/null || die "can't unpack $1" ;;
	*) tar -xzf "$1" || die "can't unpack $1" ;;
	esac
}

do_install() {
	local tag ver p os arch ext archive dir url bin
	tag=$(resolve_version "${PM_VERSION:-}" "${PM_ACTION_REF:-}")
	ver=${tag#v}
	p=$(platform)
	os=${p% *}
	arch=${p#* }
	ext=tar.gz
	if [ "$os" = windows ]; then
		windows_preflight
		ext=zip
	fi
	archive="prodmask_${ver}_${os}_${arch}.${ext}"
	dir="$(runner_temp)/prodmask-$ver"
	mkdir -p "$dir"
	url="https://github.com/$PM_REPO/releases/download/$tag"
	(
		cd "$dir" || exit 1
		download "$url/$archive" "$archive"
		download "$url/checksums.txt" checksums.txt
		verify_archive "$archive"
		unpack "$archive"
	)
	bin="$dir/prodmask"
	[ "$os" = windows ] && bin="$bin.exe"
	[ -f "$bin" ] || die "the $tag archive holds no prodmask binary"
	printf 'prodmask %s, checked against checksums.txt\n' "$ver" >&2
	output bin "$bin"
}

# GitHub's answer about this repository, as JSON.
fetch_repo_json() {
	# The token reaches curl on stdin (printf is a builtin), never on a
	# command line another process could read.
	{
		if [ -n "${PM_TOKEN:-}" ]; then printf 'Authorization: Bearer %s\n' "$PM_TOKEN"; fi
	} | curl -fsS --max-time 20 -H @- -H "X-GitHub-Api-Version: 2022-11-28" \
		-H "Accept: application/vnd.github+json" \
		"${GITHUB_API_URL:-https://api.github.com}/repos/${GITHUB_REPOSITORY:-}"
}

# Prints true only when GitHub's answer says private: true. Anything else
# (false, an error, an empty answer, no jq) prints false, so a public
# repository never gets a summary by mistake.
repo_private() {
	local json
	# jq.exe on Windows ends its lines with CRLF.
	if have jq && json=$(fetch_repo_json 2>/dev/null) &&
		[ "$(printf '%s' "$json" | jq -r .private 2>/dev/null | tr -d '\r')" = true ]; then
		echo true
	else
		echo false
	fi
}

do_visibility() { output private "$(repo_private)"; }

# want_summary <auto|true|false> <private>
want_summary() {
	case "$1" in
	true) return 0 ;;
	auto) [ "$2" = true ] ;;
	*) return 1 ;;
	esac
}

# Appends the report to the job summary, cut at a line under GitHub's limit.
write_summary() {
	local note limit
	note=$'\n\n*The report was cut here: a job summary holds at most 1 MiB. The whole report is in the file the action\'s report output names.*\n'
	if [ "$(wc -c <"$1" | tr -d ' ')" -le "$PM_SUMMARY_LIMIT" ]; then
		cat "$1" >>"$GITHUB_STEP_SUMMARY"
		return
	fi
	limit=$((PM_SUMMARY_LIMIT - ${#note}))
	head -c "$limit" "$1" | sed '$d' >>"$GITHUB_STEP_SUMMARY"
	printf '%s' "$note" >>"$GITHUB_STEP_SUMMARY"
}

do_scan() {
	local fail_on="${PM_FAIL_ON:-high}" preset="${PM_PRESET:-auto}" summary="${PM_SUMMARY:-auto}"
	local report code written=false
	[[ $fail_on =~ ^[a-z]+$ ]] || die "fail-on is none, low, medium, high or critical"
	[[ $preset =~ ^[a-z0-9]+$ ]] || die "preset is a name such as auto or wordpress"
	case "$summary" in
	auto | true | false) ;;
	*) die "summary is auto, true or false" ;;
	esac
	[ -n "${PRODMASK_DSN:-}" ] || die "the dsn input is empty"
	[ -n "${PM_BIN:-}" ] || die "prodmask isn't installed"
	report="${PM_REPORT:-}"
	[ -n "$report" ] || report="$(runner_temp)/prodmask-report.md"
	mkdir -p "$(dirname "$report")"
	rm -f "$report"
	# The DSN and password reach prodmask as PRODMASK_DSN and
	# PRODMASK_PASSWORD. The report goes to its file, never to the log.
	code=0
	"$PM_BIN" scan --format markdown --out "$report" --force --fail-on "$fail_on" --preset "$preset" >/dev/null || code=$?
	output exit-code "$code"
	output report "$(native_path "$report")"
	if [ -f "$report" ] && want_summary "$summary" "${PM_PRIVATE:-false}"; then
		write_summary "$report"
		written=true
	fi
	output summary-written "$written"
	return "$code"
}

main() {
	case "${1:-}" in
	install) do_install ;;
	visibility) do_visibility ;;
	scan) do_scan ;;
	*) die "usage: action.sh install|visibility|scan" ;;
	esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	set -euo pipefail
	main "$@"
fi
