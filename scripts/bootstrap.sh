#!/usr/bin/env bash
# bootstrap.sh - bring up node_exporter, Prometheus and Grafana from Homebrew
# for patched: the textfile dir, a Prometheus that scrapes node_exporter and
# loads patched's rules, and a Grafana with a Prometheus datasource and the
# patched board provisioned.
#
#   scripts/bootstrap.sh --dry-run      # print every step, touch nothing
#   scripts/bootstrap.sh                # do it (asks first, on the terminal)
#   scripts/bootstrap.sh --force        # also replace a stack it did not write
#
# Homebrew only, as your own user: never sudo. All three run as
# `brew services` (user LaunchAgents) bound to 127.0.0.1. Safe to re-run: a
# file that is already right is left alone, and only a service whose config
# changed is restarted. Every path it writes is under `brew --prefix`.
#
# It will not replace a Prometheus or Grafana setup it did not write: a
# prometheus.yml without its marker line, a prometheus.args that is not the
# one it writes, or a grafana.ini whose provisioning already points elsewhere
# stops it before anything is installed or written (exit 3, the same in a
# dry run). Brew's own stock prometheus.yml and prometheus.args are not
# foreign: replacing them loses nothing. --force replaces the rest, each kept
# as FILE.bak-YYYYMMDD, or FILE.bak-YYYYMMDD-HHMMSS when that name already
# holds an earlier backup.
#
# It never writes through a symlink: if prometheus.yml, prometheus.args,
# grafana.ini or any file it writes is a link (into a repo, say), or sits
# under a linked directory that leads out of the prefix, it stops the same
# way, exit 3, and --force does not override that. Replace the link by hand,
# then re-run. A prefix that is itself a link is fine: it is resolved first.
#
# Assets (the board and the rules) come from the repo this script sits in,
# or from --assets DIR|URL. A SHA256SUMS beside them is checked when present.
#
# Written for the bash that ships with macOS (3.2): no associative arrays,
# no mapfile.
set -euo pipefail

# The Homebrew prefixes patched finds by itself (Apple silicon, Intel), and
# so its default textfile dir; any other prefix it finds only when the shell
# sets HOMEBREW_PREFIX. The one list of them here; everything written uses $PREFIX.
PATCHED_FINDS_PREFIXES="/opt/homebrew /usr/local"
FORMULAE="node_exporter prometheus grafana"
# The board pins this datasource uid on every panel; provision it as-is.
DATASOURCE_UID=PBFA97CFB590B2093
BOARD_ASSET=grafana/patched.json
RULES_ASSET=prometheus/patched.rules.yml
# The first line of the prometheus.yml this script writes: how a re-run knows
# the file is its own. prometheus.args cannot carry it (brew word-splits that
# file into argv), so args are judged by content instead.
MARKER="# Written by patched's scripts/bootstrap.sh"
# The exit when it refuses to replace files it did not write.
FOREIGN_EXIT=3
# The file this script was read from; empty when it came on stdin (curl ...
# | bash). Taken here at the top level: inside a function, bash 5 reading
# stdin names the bash binary in BASH_SOURCE[0], where 3.2 leaves it unset.
SELF=${BASH_SOURCE[0]:-}

DRY_RUN=0
YES=0
FORCE=0
ASSETS=""
FOREIGN=""      # files it did not write, one "FILE: why" per line
LINKS=""        # paths it would write through a link, one "PATH: why" per line
PREAL=""        # the prefix's real path (pwd -P): every write must land under it
CHANGED=" "     # services whose config this run changed, space-delimited
WORK=""

usage() {
	cat <<'EOF'
usage: bootstrap.sh [--dry-run|-n] [--yes|-y] [--force] [--assets DIR|URL] [--help|-h]

Install node_exporter, Prometheus and Grafana with Homebrew and wire them
up for patched, all on 127.0.0.1 (9100, 9090, 3000). No sudo.

  -n, --dry-run       print every step and the changes it would make; touch nothing
  -y, --yes           do not ask before changing anything
      --force         replace a prometheus.yml, prometheus.args or grafana.ini
                      this script did not write (each kept as FILE.bak-<date>[-<time>]);
                      without it, such a file stops the run before any change.
                      A symlinked config (or a linked dir out of the prefix)
                      stops it even with --force
      --assets SRC    where grafana/patched.json and prometheus/patched.rules.yml
                      live: a directory, or an http(s) base URL (default: the
                      repo this script is in). A SHA256SUMS there is checked.
  -h, --help          this text
EOF
}

say() { printf '%s\n' "$*"; }
step() { printf '\n==> %s\n' "$*"; }
ok() { printf 'ok    %s\n' "$*"; }
die() { printf 'bootstrap: %s\n' "$*" >&2; exit 1; }

# prefix_note TEXTFILE: nothing when patched finds $PREFIX by itself; else how
# it finds it (HOMEBREW_PREFIX, which `brew shellenv` sets) or the export.
prefix_note() {
	local p
	for p in $PATCHED_FINDS_PREFIXES; do
		if [[ $PREFIX == "$p" ]]; then
			return 0
		fi
	done
	say "note: patched finds this prefix when your shell sets HOMEBREW_PREFIX (\`brew shellenv\` does)."
	say "      If it does not, add this to your shell profile:"
	say "        export PATCHED_TEXTFILE_DIR=$1"
}
cleanup() { if [[ -n $WORK ]]; then rm -rf "${WORK:?}"; fi; }

# run CMD...: the only way a command that changes anything is executed.
# Under --dry-run it prints and returns. stdin is closed so nothing it runs
# can eat the script when it is piped into bash.
run() {
	if ((DRY_RUN)); then
		say "would: $*"
		return 0
	fi
	say "run:   $*"
	"$@" </dev/null
}

mark_changed() {
	case $CHANGED in *" $1 "*) ;; *) CHANGED="$CHANGED$1 " ;; esac
}

changed() {
	case $CHANGED in *" $1 "*) return 0 ;; *) return 1 ;; esac
}

ensure_dir() {
	if [[ -d $1 ]]; then
		ok "$1/"
	else
		run mkdir -p "$1"
	fi
}

# backup FILE: copy FILE aside before put replaces it. Never skipped: the
# copy is FILE.bak-YYYYMMDD, and when that name already holds something else
# (an earlier run's backup, the same day) it is FILE.bak-YYYYMMDD-HHMMSS,
# then -2, -3 ... An existing backup is never overwritten. A FILE equal to
# the backup already under the name it would take is not copied twice. No
# config reader's glob matches any of these names.
backup() {
	local file=$1 stamp bak n=1
	stamp=$(date +%Y%m%d-%H%M%S)
	bak=$file.bak-${stamp%-*}
	if [[ -e $bak || -L $bak ]]; then
		if cmp -s "$file" "$bak"; then
			say "      already kept as $bak"
			return 0
		fi
		bak=$file.bak-$stamp
		while [[ -e $bak || -L $bak ]]; do
			if cmp -s "$file" "$bak"; then
				say "      already kept as $bak"
				return 0
			fi
			n=$((n + 1))
			bak=$file.bak-$stamp-$n
		done
	fi
	cp -p "$file" "$bak"
	say "      kept the old one as $bak"
}

# bak_names: how the refusal and the --force header name the backups.
bak_names() {
	local day
	day=$(date +%Y%m%d)
	printf 'each kept as FILE.bak-%s, or FILE.bak-%s-HHMMSS when that name already holds an earlier backup' "$day" "$day"
}

# put FILE SERVICE: content on stdin. The one primitive every file write
# goes through. Equal content: say ok and do nothing. Otherwise show the
# change, back the old file up (backup, above), write it, and mark SERVICE
# changed. FILE a symlink, or under a linked directory that leads out of the
# prefix: refuse (exit 3, dry run too), never write through it. The
# preflight (check_links) stops every path first; this is the backstop.
put() {
	local file=$1 svc=$2 new why
	why=$(link_trouble "$file")
	if [[ -n $why ]]; then
		{
			say "bootstrap: refusing to write $file: $why. This script never writes through a link."
			say "Nothing more was changed. Replace the link by hand, then re-run. --force does not override this."
		} >&2
		exit "$FOREIGN_EXIT"
	fi
	new=$(mktemp "$WORK/put.XXXXXX")
	cat >"$new"
	if [[ -f $file ]] && cmp -s "$new" "$file"; then
		ok "$file"
		return 0
	fi
	mark_changed "$svc"
	if ((DRY_RUN)); then
		say "would: write $file"
		if [[ -f $file ]]; then
			diff -u --label "$file" --label "$file (planned)" "$file" "$new" | sed 's/^/        /' || true
		else
			say "        (new file, $(wc -l <"$new" | tr -d ' ') lines)"
		fi
		return 0
	fi
	say "write $file"
	if [[ -f $file ]]; then
		backup "$file"
	fi
	mkdir -p "$(dirname "$file")"
	cat "$new" >"$file"
}

# ini_set SECTION KEY VALUE < ini > ini: set KEY in [SECTION], replacing the
# key or its commented-out form (;key / #key) if there, adding it if not.
ini_set() {
	awk -v sec="$1" -v key="$2" -v val="$3" '
		function header(line) { return line ~ /^[ \t]*\[[^]]*\][ \t]*$/ }
		BEGIN { insec = 0; done = 0; seen = 0 }
		header($0) {
			if (insec && !done) { print key " = " val; done = 1 }
			s = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", s)
			insec = (s == sec); if (insec) seen = 1
			print; next
		}
		insec && !done && $0 ~ ("^[ \t]*[;#]?[ \t]*" key "[ \t]*=") {
			print key " = " val; done = 1; next
		}
		{ print }
		END {
			if (!done) {
				if (!seen) print "\n[" sec "]"
				print key " = " val
			}
		}'
}

sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

# Check each asset against SUMS (sha256sum format), if SUMS is a file.
check_sums() {
	local sums=$1 dir=$2 rel want
	if [[ ! -f $sums ]]; then
		say "      no SHA256SUMS beside the assets: not checked"
		return 0
	fi
	for rel in "$BOARD_ASSET" "$RULES_ASSET"; do
		want=$(awk -v f="$rel" '{ p = $2; sub(/^\*/, "", p) } p == f { print $1; exit }' "$sums")
		[[ -n $want ]] || die "SHA256SUMS does not list $rel: stopping before anything is touched"
		[[ $(sha256 "$dir/$rel") == "$want" ]] ||
			die "$rel does not match SHA256SUMS: stopping before anything is touched"
		ok "sha256 $rel"
	done
}

# fetch URL FILE: 0 on 200, 2 on 404, die on anything else.
fetch() {
	local code
	mkdir -p "$(dirname "$2")"
	code=$(curl -sS -L -o "$2" -w '%{http_code}' "$1" </dev/null) || die "could not fetch $1"
	case $code in
	200) return 0 ;;
	404) rm -f "$2"; return 2 ;;
	*) die "fetching $1: HTTP $code" ;;
	esac
}

# Sets ASSET_DIR to a directory holding both assets, checked.
load_assets() {
	local src=$ASSETS rel rc
	if [[ -z $src ]]; then
		# Read from stdin (curl ... | bash): no file, so no repo beside it.
		[[ -n $SELF ]] ||
			die "assets not found: the script was read from stdin, so there is no repo beside it: piped: pass --assets URL"
		src=$(cd "$(dirname "$SELF")/.." 2>/dev/null && pwd) || src=""
	fi
	case $src in
	http://* | https://*)
		ASSET_DIR="$WORK/assets"
		for rel in "$BOARD_ASSET" "$RULES_ASSET"; do
			rc=0
			fetch "${src%/}/$rel" "$ASSET_DIR/$rel" || rc=$?
			((rc == 0)) || die "${src%/}/$rel: not found (HTTP 404)"
		done
		# Absent (404) is allowed: check_sums then says it was not checked.
		fetch "${src%/}/SHA256SUMS" "$ASSET_DIR/SHA256SUMS" || true
		;;
	*)
		ASSET_DIR=$src
		;;
	esac
	for rel in "$BOARD_ASSET" "$RULES_ASSET"; do
		[[ -n $ASSET_DIR && -s $ASSET_DIR/$rel ]] ||
			die "asset $rel not found under '${ASSET_DIR:-?}': pass --assets DIR|URL"
	done
	if ! grep -q '"uid": "patched"' "$ASSET_DIR/$BOARD_ASSET" ||
		! grep -q "$DATASOURCE_UID" "$ASSET_DIR/$BOARD_ASSET"; then
		die "$ASSET_DIR/$BOARD_ASSET is not the patched board"
	fi
	grep -q '^groups:' "$ASSET_DIR/$RULES_ASSET" ||
		die "$ASSET_DIR/$RULES_ASSET is not a Prometheus rules file"
	ok "assets in $src"
	check_sums "$ASSET_DIR/SHA256SUMS" "$ASSET_DIR"
}

# prom_args ETC: the prometheus.args this script writes. Brew's stock file
# holds these same three flags, so replacing a stock one loses nothing.
prom_args() {
	cat <<EOF
--config.file $1/prometheus.yml
--web.listen-address=127.0.0.1:9090
--storage.tsdb.path $PREFIX/var/prometheus
EOF
}

# brew_stock_yml: the prometheus.yml Homebrew's prometheus formula installs,
# byte for byte (129 bytes). Source: homebrew-core Formula/p/prometheus.rb,
# its (buildpath/"prometheus.yml").write <<~YAML heredoc, which etc.install
# puts in place. It scrapes only Prometheus itself, so replacing it loses
# nothing; a first run that stopped after `brew install prometheus` leaves
# it. Judged by content, as prometheus.args is: one byte off is foreign.
brew_stock_yml() {
	cat <<'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "prometheus"
    static_configs:
    - targets: ["localhost:9090"]
EOF
}

# ini_other SECTION KEY WANT < ini: the first ACTIVE (uncommented) KEY in
# [SECTION] whose value is not WANT, or nothing. A ;key or #key is a comment.
ini_other() {
	awk -v sec="$1" -v key="$2" -v want="$3" '
		function header(line) { return line ~ /^[ \t]*\[[^]]*\][ \t]*$/ }
		header($0) { s = $0; gsub(/^[ \t]*\[|\][ \t]*$/, "", s); insec = (s == sec); next }
		insec && $0 ~ ("^[ \t]*" key "[ \t]*=") {
			v = $0; sub(/^[^=]*=[ \t]*/, "", v); sub(/[ \t\r]+$/, "", v)
			if (v ~ /^".*"$/) v = substr(v, 2, length(v) - 2)
			if (v != want) { print (v == "" ? "(empty)" : v); exit }
		}'
}

foreign() { FOREIGN="$FOREIGN$1: $2"$'\n'; }

# first_link PATH: the first component of PATH below $PREFIX that is a
# symlink, as "COMPONENT -> TARGET", or nothing. PREFIX itself is not looked
# at: a prefix that is a link (a relocated brew) is Homebrew's layout.
first_link() {
	local rest cur=$PREFIX part
	[[ $1 == "$PREFIX"/* ]] || return 0
	rest=${1#"$PREFIX"/}
	while [[ -n $rest ]]; do
		part=${rest%%/*}
		cur=$cur/$part
		if [[ -L $cur ]]; then
			printf '%s -> %s' "$cur" "$(readlink "$cur")"
			return 0
		fi
		if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=""; fi
	done
}

# leaves DIR: why a write under DIR would land outside the prefix, or nothing.
# DIR's real path is the cd + pwd -P of its nearest EXISTING ancestor (what
# mkdir -p builds under; bash 3.2 has no realpath), and it must be $PREAL or
# below it by path component, never by a bare string prefix.
leaves() {
	local dir=$1 d real link
	d=$dir
	while [[ ! -e $d && ! -L $d ]]; do d=$(dirname "$d"); done
	real=$(cd "$d" 2>/dev/null && pwd -P) || real=""
	if [[ -n $real ]] && [[ $real == "$PREAL" || $real == "$PREAL"/* ]]; then
		return 0
	fi
	link=$(first_link "$dir")
	if [[ -n $link ]]; then
		printf 'under %s, which leads out of the prefix (%s)' "$link" "$PREAL"
	else
		printf '%s resolves to %s, outside the prefix (%s)' "$d" "${real:-nowhere}" "$PREAL"
	fi
}

# link_trouble FILE: why writing FILE would write through a link, or nothing.
# FILE itself a symlink (wherever it points), or its directory leading out of
# the prefix.
link_trouble() {
	if [[ -L $1 ]]; then
		printf 'it is a symlink (-> %s)' "$(readlink "$1")"
		return 0
	fi
	leaves "$(dirname "$1")"
}

# check_links FILE...: note in LINKS each path this run would write (a file,
# or DIR/. for a directory it makes) that is a symlink or sits under a link
# out of the prefix. Writing it would write outside the prefix, so no flag
# overrides this. Reads only.
check_links() {
	local path why
	for path in "$@"; do
		why=$(link_trouble "$path")
		if [[ -n $why ]]; then
			LINKS="$LINKS${path%/.}: $why"$'\n'
		fi
	done
}

# check_owner ETC PROV: note in FOREIGN each file step 4 or 5 would replace
# that this script did not write. Reads only.
check_owner() {
	local etc=$1 prov=$2 file other
	file=$etc/prometheus.yml
	if [[ -f $file ]] && ! grep -qF "$MARKER" "$file" && ! brew_stock_yml | cmp -s - "$file"; then
		foreign "$file" "it has no \"$MARKER\" line"
	fi
	file=$etc/prometheus.args
	if [[ -f $file ]] && ! prom_args "$etc" | cmp -s - "$file"; then
		foreign "$file" "it is not the three flags this script writes"
	fi
	file=$etc/grafana/grafana.ini
	if [[ -f $file ]]; then
		other=$(ini_other paths provisioning "$prov" <"$file")
		if [[ -n $other ]]; then
			foreign "$file" "its [paths] provisioning is $other, not $prov"
		fi
	fi
}

list_foreign() { printf '%s' "$FOREIGN" | sed 's/^/  /'; }

confirm() {
	if ((DRY_RUN || YES)); then return 0; fi
	if ! { : </dev/tty; } 2>/dev/null; then
		die "no terminal to ask on: re-run with --yes, or --dry-run to see the plan"
	fi
	local answer="" ask="Proceed?"
	[[ -z $FOREIGN ]] || ask="Replace the files listed above (not written by this script) and proceed?"
	printf '%s [y/N] ' "$ask" >/dev/tty
	read -r answer </dev/tty || true
	case $answer in
	y | Y | yes | YES) ;;
	*) die "stopped: nothing was changed" ;;
	esac
}

service_status() {
	brew services list </dev/null 2>/dev/null | awk -v s="$1" '$1 == s { print $2; exit }'
}

main() {
	while (($#)); do
		case $1 in
		-n | --dry-run) DRY_RUN=1 ;;
		-y | --yes) YES=1 ;;
		--assets)
			[[ $# -ge 2 && -n $2 ]] || die "--assets needs a directory or URL"
			ASSETS=$2
			shift
			;;
		--assets=*) ASSETS=${1#--assets=} ;;
		--force) FORCE=1 ;;
		-h | --help) usage; return 0 ;;
		*) usage >&2; die "unknown argument: $1" ;;
		esac
		shift
	done

	step "0/7 Preflight"
	[[ $(uname -s) == Darwin ]] || die "this is for macOS"
	[[ $(id -u) -ne 0 ]] || die "run as your own user, not root: Homebrew and this script never need sudo"
	command -v brew >/dev/null || die "Homebrew is not on PATH: install it first (https://brew.sh)"
	PREFIX=$(brew --prefix </dev/null)
	[[ -n $PREFIX && -d $PREFIX ]] || die "brew --prefix gave '$PREFIX'"
	[[ -w $PREFIX ]] || die "$PREFIX is not writable by $(id -un): fix Homebrew's ownership; this script will not sudo"
	PREAL=$(cd "$PREFIX" && pwd -P) || die "cannot resolve $PREFIX"
	WORK=$(mktemp -d "${TMPDIR:-/tmp}/bootstrap.XXXXXX")
	trap cleanup EXIT
	ok "macOS, user $(id -un), Homebrew at $PREFIX"
	load_assets

	local etc=$PREFIX/etc
	local textfile=$PREFIX/var/lib/node_exporter/textfile_collector
	local rules_dir=$etc/prometheus-rules
	local gf=$etc/grafana
	local prov=$gf/provisioning
	local boards=$gf/dashboards/security

	# Before the prompt and step 1: nothing installed or written yet.
	# Every path a step writes or makes (a directory as DIR/.): none may be a
	# link, or lead through one out of the prefix.
	check_links "$etc/prometheus.yml" "$etc/prometheus.args" "$gf/grafana.ini" \
		"$etc/node_exporter.args" "$rules_dir/patched.rules.yml" \
		"$prov/datasources/prometheus.yml" "$prov/dashboards/patched.yml" "$boards/patched.json" \
		"$textfile/." "$prov/alerting/." "$prov/plugins/."
	if [[ -n $LINKS ]]; then
		{
			say "bootstrap: refusing: this run would write through a symlink, and this script never does:"
			printf '%s' "$LINKS" | sed 's/^/  /'
			say "Nothing was changed. --force does not override this: replace each link by hand with a regular file or directory, then re-run."
		} >&2
		exit "$FOREIGN_EXIT"
	fi
	ok "nothing it writes is, or is under, a symlink out of $PREAL"
	check_owner "$etc" "$prov"
	if [[ -n $FOREIGN ]] && ! ((FORCE)); then
		{
			say "bootstrap: refusing: these files were not written by this script, and replacing them would drop the setup they hold:"
			list_foreign
			say "Nothing was changed. --force replaces them ($(bak_names))."
		} >&2
		exit "$FOREIGN_EXIT"
	fi
	[[ -n $FOREIGN ]] || ok "no file here that this script did not write"

	if ((DRY_RUN)); then
		say ""
		say "DRY RUN: every step below is printed; nothing is installed, written or restarted."
	else
		say ""
		say "This installs (if missing) $FORMULAE with Homebrew, writes their"
		say "config under $PREFIX (backing up any file it changes), and starts or"
		say "restarts them as brew services on 127.0.0.1. --dry-run shows every change."
	fi
	if [[ -n $FOREIGN ]]; then
		say ""
		if ((DRY_RUN)); then
			say "--force: these files were not written by this script, and a real run REPLACES them"
		else
			say "--force: these files were not written by this script, and this run REPLACES them"
		fi
		say "($(bak_names)):"
		list_foreign
	fi
	confirm

	step "1/7 Install"
	local f
	for f in $FORMULAE; do
		if brew list --formula "$f" >/dev/null 2>&1 </dev/null; then
			ok "$f installed"
		else
			run brew install "$f"
		fi
	done

	step "2/7 Textfile dir"
	ensure_dir "$textfile"
	prefix_note "$textfile"

	step "3/7 node_exporter"
	put "$etc/node_exporter.args" node_exporter <<EOF
--web.listen-address=127.0.0.1:9100
--collector.textfile.directory=$textfile
EOF

	step "4/7 Prometheus"
	if command -v promtool >/dev/null; then
		promtool check rules "$ASSET_DIR/$RULES_ASSET" </dev/null >/dev/null ||
			die "promtool rejects $RULES_ASSET: nothing written for Prometheus"
		ok "promtool check rules $RULES_ASSET"
	else
		say "      promtool not installed yet: rules checked after the install"
	fi
	put "$rules_dir/patched.rules.yml" prometheus <"$ASSET_DIR/$RULES_ASSET"
	put "$etc/prometheus.yml" prometheus <<EOF
$MARKER. A re-run puts it back;
# the file it replaced is kept as prometheus.yml.bak-<date>.
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - $rules_dir/*.yml

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["127.0.0.1:9090"]
  - job_name: node
    static_configs:
      - targets: ["127.0.0.1:9100"]
EOF
	prom_args "$etc" >"$WORK/prometheus.args"
	put "$etc/prometheus.args" prometheus <"$WORK/prometheus.args"

	step "5/7 Grafana"
	local ini=$gf/grafana.ini cur=$WORK/grafana.ini.cur
	if [[ -f $ini ]]; then
		cp "$ini" "$cur"
	else
		: >"$cur"
		say "      $ini comes with the grafana install: the two keys are planned against an empty file"
	fi
	# Rendered to a file, not piped into put: a pipeline runs put in a
	# subshell, and the service it marks changed would be lost.
	ini_set paths provisioning "$prov" <"$cur" | ini_set server http_addr 127.0.0.1 >"$cur.new"
	put "$ini" grafana <"$cur.new"
	put "$prov/datasources/prometheus.yml" grafana <<EOF
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    uid: $DATASOURCE_UID
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    editable: false
EOF
	put "$prov/dashboards/patched.yml" grafana <<EOF
apiVersion: 1
providers:
  - name: patched
    folder: Security
    type: file
    allowUiUpdates: false
    options:
      path: $boards
EOF
	put "$boards/patched.json" grafana <"$ASSET_DIR/$BOARD_ASSET"
	ensure_dir "$prov/alerting"
	ensure_dir "$prov/plugins"

	step "6/7 Services"
	if ! ((DRY_RUN)) && changed prometheus && command -v promtool >/dev/null; then
		promtool check config "$etc/prometheus.yml" </dev/null >/dev/null ||
			die "promtool rejects $etc/prometheus.yml: Prometheus not restarted"
		ok "promtool check config"
	fi
	local status
	for f in $FORMULAE; do
		status=$(service_status "$f")
		if changed "$f"; then
			run brew services restart "$f"
		elif [[ $status != started ]]; then
			run brew services start "$f"
		else
			ok "$f started"
		fi
	done

	step "7/7 Done"
	say "Grafana:       http://127.0.0.1:3000/d/patched  (first login admin/admin; it asks you to change it)"
	say "Prometheus:    http://127.0.0.1:9090"
	say "node_exporter: http://127.0.0.1:9100/metrics"
	if [[ -f $ASSET_DIR/pyproject.toml ]] && grep -q '^name = "patched"$' "$ASSET_DIR/pyproject.toml"; then
		say "Next: install patched from this checkout: uv tool install $ASSET_DIR"
		say "      then run: patched scan"
	else
		say "Next: install patched: uv tool install git+https://github.com/mbailey/patched"
		say "      then run: patched scan"
	fi
	if ((DRY_RUN)); then
		say ""
		say "Dry run: nothing was changed. Run again without --dry-run to apply."
	fi
}

main "$@"
