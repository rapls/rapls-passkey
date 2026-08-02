#!/usr/bin/env bash
#
# Assemble the verification bundle (rapls-passkey-tests.zip) and the submission
# archive that carries it.
#
#   bin/make-bundle.sh [--out /path/to/plugins-dir] [--ci-artifacts /path/to/json-dir]
#
# The bundle is built from the TESTED COMMIT — `git archive`, plus `vendor/`,
# which is generated rather than tracked and is checked against
# vendor-manifest.json before it is copied (V83-01, V84-01). Reading the working
# directory instead is how a local editor's settings file, with machine paths and
# database credentials in it, ended up in a bundle sent for review (V34-05).
# Nothing untracked is included unless it is named here.
#
# Lives in bin/ (never shipped).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGINS="$(cd "$ROOT/.." && pwd)"
CI_ARTIFACTS=""
CI_RUN=""
# Reading the artifacts' provenance needs a JSON parser; php is already required
# to build a package at all. Override with PHP=/path/to/php, as the other scripts do.
PHP_BIN="${PHP:-php}"

while [ $# -gt 0 ]; do
	case "$1" in
		--out) PLUGINS="$2"; shift 2 ;;
		--ci-artifacts) CI_ARTIFACTS="$2"; shift 2 ;;
		--ci-run) CI_RUN="$2"; shift 2 ;;
		*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

FREE="$PLUGINS/rapls-passkey"
PRO="$PLUGINS/rapls-passkey-pro"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Never in the bundle, whatever git says: the live licence configuration and the
# licence data hold secrets.
SECRETS=(
	"tools/license-server/rpls-license-config.php"
	"tools/license-server/rpls-license-data.json"
)

# FROM THE COMMIT, NOT FROM THE DESK (V83-01).
#
# This used to take the file LIST from git and the file CONTENTS from the working
# tree, and every check afterwards compared commits — so editing a tracked file
# without committing it put the edit in the bundle while `git rev-parse HEAD`
# went on naming the tested commit and every gate passed. The distribution ZIPs'
# source_dirty flag did not help: that is a property of those ZIPs, not of the
# source staged here, and the licence server is staged here.
#
# So the tree comes out of the commit with `git archive`, and a dirty checkout is
# refused outright rather than silently exported. Two independent things: even if
# a future edit reintroduced a copy from the working tree, the clean-tree gate
# would still catch it.
require_clean() {
	local src="$1" slug="$2" dirty
	dirty="$( cd "$src" && git status --porcelain --untracked-files=no )"
	if [ -n "$dirty" ]; then
		echo "refusing to build: $slug has uncommitted changes, and the bundle carries its source" >&2
		printf '%s\n' "$dirty" | sed 's/^/  /' >&2
		exit 1
	fi
}

stage_plugin() {
	local src="$1" slug="$2" dest="$STAGE/$2" commit
	[ -d "$src" ] || return 0

	require_clean "$src" "$slug"
	commit="$( cd "$src" && git rev-parse HEAD )"

	mkdir -p "$dest"
	# The tracked tree AS COMMITTED. git archive writes exactly what is in the
	# commit; nothing on this machine can differ from it.
	( cd "$src" && git archive --format=tar "$commit" ) | ( cd "$dest" && tar -xf - )

	# Never in the bundle, whatever the commit says.
	for secret in "${SECRETS[@]}"; do
		rm -f "$dest/$secret"
	done

	# vendor/ is generated, not tracked, and the suites need it — so it is the one
	# thing here that does not come out of the commit, and it is the thing that
	# runs on a reviewer's machine when they execute verify.sh.
	#
	# CHECKED AGAINST THE RECORDED TREE, NOT DESCRIBED (V84-01). The previous
	# version wrote the digests of composer.lock and installed.json into
	# VENDOR-PROVENANCE.json — neither of which changes when vendor/autoload.php
	# does. Nothing read that file afterwards either. bin/vendor-digest.php
	# compares every path, type, executable bit and content against
	# vendor-manifest.json as committed, and this refuses on any difference. The
	# provenance file stays, now recording the tree digest that was verified
	# rather than two numbers that were not.
	if [ -d "$src/vendor" ]; then
		if [ ! -f "$src/bin/vendor-digest.php" ]; then
			echo "refusing to build: $slug has a vendor/ and no bin/vendor-digest.php to check it" >&2
			exit 1
		fi
		( cd "$src" && "$PHP_BIN" bin/vendor-digest.php --check ) || {
			echo "refusing to build: $slug's vendor/ is not the dependency tree it recorded" >&2
			exit 1
		}
		rsync -a --exclude '.git' "$src/vendor/" "$dest/vendor/"
		printf '{\n  "vendor_tree_sha256": "%s",\n  "verified_against": "vendor-manifest.json",\n  "composer_lock_sha256": "%s",\n  "from_commit": "%s"\n}\n' \
			"$( cd "$src" && "$PHP_BIN" bin/vendor-digest.php --print )" \
			"$( [ -f "$dest/composer.lock" ] && shasum -a 256 "$dest/composer.lock" | cut -d' ' -f1 || echo 'absent' )" \
			"$commit" \
			> "$dest/vendor/VENDOR-PROVENANCE.json"
	fi

	# The scoper PHAR is 8 MB of third-party binary; the build script fetches it.
	rm -f "$dest/bin/php-scoper.phar"
}

stage_plugin "$FREE" rapls-passkey
stage_plugin "$PRO" rapls-passkey-pro

# The reproduction script, with the digests of the ZIPs it is meant to check.
FREE_SHA="$(shasum -a 256 "$PLUGINS/rapls-passkey.zip" | cut -d' ' -f1)"
PRO_SHA="$(shasum -a 256 "$PLUGINS/rapls-passkey-pro.zip" | cut -d' ' -f1)"

# THE RELEASE METADATA MUST NAME THE ARTIFACT GOING INTO THIS BUNDLE (V61-01).
#
# update-info.json is written by hand after the build, and a release once went
# out announcing 0.14.63 over a 0.14.62 ZIP because a shell chain silently
# skipped the version bump. bin/verify-dist.php compares the version and the
# sequence; it deliberately does NOT compare the digest, because any rebuild is
# a different artifact by design. Here is the one place where the digest IS a
# release property: this bundle is the thing being submitted, and the metadata
# has to describe the ZIP inside it.
# MISSING IS A FAILURE (V62-09). This used to run only when both files existed,
# so a misplaced update-info.json skipped the check that exists to catch a
# misplaced update-info.json.
if [ -f "$PLUGINS/rapls-passkey-pro.zip" ] && [ ! -f "$PRO/tools/license-server/update-info.json" ]; then
	echo "refusing to build: a Pro ZIP is being bundled but tools/license-server/update-info.json is missing (V62-09)" >&2
	exit 1
fi
if [ -f "$PRO/tools/license-server/update-info.json" ] && [ -f "$PLUGINS/rapls-passkey-pro.zip" ]; then
	PRO_ZIP_VER="$(unzip -p "$PLUGINS/rapls-passkey-pro.zip" rapls-passkey-pro/rapls-passkey-pro.php 2>/dev/null |
		sed -n 's/^[[:space:]]*\*[[:space:]]*Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -1)"
	PRO_ZIP_SEQ="$(unzip -p "$PLUGINS/rapls-passkey-pro.zip" rapls-passkey-pro/rapls-passkey-pro.php 2>/dev/null |
		sed -n "s/.*RAPLS_PASSKEY_PRO_RELEASE_SEQUENCE'[[:space:]]*,[[:space:]]*\([0-9]*\).*/\1/p" | head -1)"
	INFO="$PRO/tools/license-server/update-info.json"
	INFO_VER="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INFO" | head -1)"
	INFO_SEQ="$(sed -n 's/.*"release_sequence"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$INFO" | head -1)"
	INFO_SHA="$(sed -n 's/.*"sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$INFO" | head -1)"

	if [ "$INFO_VER" != "$PRO_ZIP_VER" ] || [ "$INFO_SEQ" != "$PRO_ZIP_SEQ" ] || [ "$INFO_SHA" != "$PRO_SHA" ]; then
		echo "refusing to build: update-info.json does not describe the Pro ZIP (V61-01)" >&2
		echo "  ZIP:          version $PRO_ZIP_VER, sequence $PRO_ZIP_SEQ, sha $PRO_SHA" >&2
		echo "  update-info:  version $INFO_VER, sequence $INFO_SEQ, sha $INFO_SHA" >&2
		exit 1
	fi
	# AND THE GENERATOR AGREES (V81-04). The three fields above are compared
	# against the ZIP; last_updated is not, and it is the one that drifted. Pro's
	# own stamper re-derives all four and reports any it would have to change, so
	# wiring it in here is what makes "generated, not typed" a property of the
	# bundle rather than of whoever remembered to run it. A MISSING GENERATOR IS A
	# FAILURE, NOT A SKIP (V82-04). This was written as
	# "run it if it is there", which meant the whole last_updated invariant could
	# be removed from the release by deleting one file — and its absence would
	# have printed the same reassuring line as its success.
	if [ ! -f "$PRO/bin/stamp-release.php" ]; then
		echo "refusing to build: $PRO/bin/stamp-release.php is missing; the release metadata cannot be checked against what the release generates" >&2
		exit 1
	fi
	if ! "$PHP_BIN" "$PRO/bin/stamp-release.php" --check "$PLUGINS/rapls-passkey-pro.zip" >/dev/null 2>"$STAGE/.stamp-err"; then
		echo "refusing to build: Pro's release metadata is not what the release generates" >&2
		cat "$STAGE/.stamp-err" >&2
		echo "  (run: php bin/stamp-release.php ../rapls-passkey-pro.zip)" >&2
		exit 1
	fi
	rm -f "$STAGE/.stamp-err"
	echo "release metadata ok: $PRO_ZIP_VER / sequence $PRO_ZIP_SEQ / $PRO_SHA (regenerating it changes nothing)"
fi
sed -e "s/__FREE_SHA__/$FREE_SHA/" -e "s/__PRO_SHA__/$PRO_SHA/" \
	"$FREE/tests/db/verify-bundle.sh" > "$STAGE/verify.sh"
chmod +x "$STAGE/verify.sh"

# NEITHER ZIP MAY COME FROM A DIRTY TREE (V69-01). build-dist.sh refuses to make
# one now, but the bundle is what goes out, and it must not be possible to put a
# ZIP in it that no commit can reproduce — including one built before that check
# existed, or with ALLOW_DIRTY_BUILD set.
for z in "$PLUGINS/rapls-passkey.zip" "$PLUGINS/rapls-passkey-pro.zip"; do
	[ -f "$z" ] || continue
	slug="$(basename "$z" .zip)"
	dirty="$(unzip -p "$z" "$slug/build-manifest.json" 2>/dev/null |
		sed -n 's/.*"source_dirty": *"\([a-z]*\)".*/\1/p' | head -1)"
	if [ "$dirty" != "false" ]; then
		echo "refusing to build: $slug.zip was built from a tree that is not clean (source_dirty: ${dirty:-absent}) — V69-01" >&2
		echo "  Commit the source and rebuild; a ZIP that cannot be reproduced from its own commit is not a release." >&2
		exit 1
	fi
done
echo "provenance ok: both ZIPs were built from a clean tree"

# THE RUNBOOK EXISTS TWICE AND MUST NOT DIFFER (V68-03). One copy ships in this
# bundle, one lives in the free plugin's docs, and the test that compares them
# SKIPS wherever only one is present — which is every path except a full source
# checkout. This is the gate that always runs: no bundle is built from a
# document that has drifted, or from a missing one.
E2E_TOP="$PLUGINS/E2E-TESTING.md"
E2E_DOC="$FREE/docs/E2E-TESTING.md"
for f in "$E2E_TOP" "$E2E_DOC"; do
	[ -f "$f" ] || { echo "refusing to build: $f is missing (V68-03)" >&2; exit 1; }
done
if [ "$(shasum -a 256 "$E2E_TOP" | cut -d' ' -f1)" != "$(shasum -a 256 "$E2E_DOC" | cut -d' ' -f1)" ]; then
	echo "refusing to build: the two copies of E2E-TESTING.md differ (V68-03)" >&2
	diff -u "$E2E_DOC" "$E2E_TOP" | head -40 >&2
	exit 1
fi
echo "runbook ok: both copies of E2E-TESTING.md agree"
cp "$E2E_TOP" "$STAGE/"
[ -f "$PLUGINS/BUNDLE-README.md" ] && cp "$PLUGINS/BUNDLE-README.md" "$STAGE/README.md"

if [ -n "$CI_ARTIFACTS" ] && [ -d "$CI_ARTIFACTS" ]; then
	mkdir -p "$STAGE/ci-artifacts"
	find "$CI_ARTIFACTS" -name '*.json' -exec cp {} "$STAGE/ci-artifacts/" \;

	# WHICH RESULTS A COMPLETE RUN PRODUCES (V80-01). Read out of the workflow's
	# own matrix, so adding or removing a database changes what a bundle must
	# contain — a list maintained here by hand would agree with whatever turned
	# up, which is the failure this check exists to prevent. Each database
	# contributes four: concurrency and integration, each plain and with
	# CLIENT_FOUND_ROWS.
	#
	# FROM THE WORKFLOW AS IT WAS AT THE TESTED COMMIT (V81-03), not as it is in
	# this working tree. They are usually the same file; when they are not, the
	# working tree is the wrong authority — it describes a run that did not
	# happen. The run's own SHA is not known until the artifacts are read, so
	# this is done in two passes: identity first, then the expected sets.
	matrices_from() {   # $1 = the workflow file's text on stdin
		local dbs
		# -E, not BRE: BSD sed has no \| alternation, and a pattern that silently
		# matches nothing would make the expected set empty — which is why the
		# guard below is on the extraction and not only on the comparison.
		dbs="$( sed -nE 's/^[[:space:]]*-[[:space:]]*name:[[:space:]]*((mysql|mariadb)-[0-9.]+)[[:space:]]*$/\1/p' | sort -u )"
		[ -n "$dbs" ] || return 1
		for db in $dbs; do
			for kind in concurrency integration; do
				printf '%s-%s\n%s-%s-foundrows\n' "$kind" "$db" "$kind" "$db"
			done
		done | sort | paste -sd, -
	}
	jobs_from() {       # the seven jobs a complete run has: 3 smoke + 4 database
		local wf phps dbs
		wf="$( cat )"
		phps="$( printf '%s' "$wf" | sed -nE "s/^[[:space:]]*php:[[:space:]]*\[([^]]*)\].*/\1/p" | tr -d " '" | tr ',' '\n' | grep -v '^$' | sort -u )"
		dbs="$( printf '%s' "$wf" | sed -nE 's/^[[:space:]]*-[[:space:]]*name:[[:space:]]*((mysql|mariadb)-[0-9.]+)[[:space:]]*$/\1/p' | sort -u )"
		[ -n "$phps" ] && [ -n "$dbs" ] || return 1
		{ for p in $phps; do printf 'smoke-php-%s\n' "$p"; done
		  for d in $dbs;  do printf 'concurrency-%s\n' "$d"; done
		  # THE GATE ITSELF (V82-03). Two matrices are not "every job": a job
		  # added to this workflow later would not appear here, and a run that
		  # went red because THAT job failed would still assemble. The gate job
		  # asks the API which jobs the run really had and requires all of them,
		  # so it covers additions the day they are made; requiring its
		  # attestation here is what makes that binding.
		  printf 'release-gate\n'
		} | sort | paste -sd, -
	}

	# Pass 1: what run do the artifacts claim? (Identity only; nothing is trusted
	# yet — the strict checks run in pass 2 against that run's own workflow.)
	RUN_SHA_CLAIM="$( "$PHP_BIN" -r '
		$ids = array();
		foreach (glob($argv[1] . "/*.json") as $f) {
			$d = json_decode((string) file_get_contents($f), true);
			if (is_array($d) && isset($d["ci"]["sha"])) { $ids[(string) $d["ci"]["sha"]] = true; }
		}
		echo 1 === count($ids) ? (string) array_key_first($ids) : "";
	' "$STAGE/ci-artifacts" )"
	if [ -z "$RUN_SHA_CLAIM" ]; then
		echo "refusing to build: the CI results do not agree on one commit, or name none" >&2
		exit 1
	fi
	WORKFLOW_AT_RUN="$( cd "$FREE" && git show "$RUN_SHA_CLAIM:.github/workflows/tests.yml" 2>/dev/null )"
	if [ -z "$WORKFLOW_AT_RUN" ]; then
		echo "refusing to build: the workflow at $RUN_SHA_CLAIM could not be read (is that commit here?)" >&2
		exit 1
	fi
	EXPECTED_MATRICES="$( printf '%s' "$WORKFLOW_AT_RUN" | matrices_from )" || {
		echo "refusing to build: the database matrix could not be read from the workflow at $RUN_SHA_CLAIM" >&2
		exit 1
	}
	EXPECTED_JOBS="$( printf '%s' "$WORKFLOW_AT_RUN" | jobs_from )" || {
		echo "refusing to build: the job list could not be read from the workflow at $RUN_SHA_CLAIM" >&2
		exit 1
	}
	# Where they came from, written here rather than described in a README that
	# outlives the run it names (V50-07).
	#
	# READ OUT OF THE ARTIFACTS, NOT ASSERTED OVER THEM (V79-04). This used to
	# write "${CI_RUN:-unknown}" — and with no --ci-run given it shipped
	# run_id "unknown" beside a reply that named a specific run, so the one
	# association the bundle exists to record was the one thing in it nobody
	# could check. The workflow stamps each result file with the run that wrote
	# it; this reads them back, requires every file to name the SAME run, and
	# refuses to build if any of them cannot say. An operator-supplied --ci-run
	# is now a cross-check, not the source.
	#
	# Two different commits, and conflating them is how a bundle claims to have
	# tested code it did not ship. The ZIP's commit is read out of the artifact
	# itself (build-manifest.json) because that is what a reproducer must check
	# out; the repository head is what CI ran. A release-metadata commit made
	# after the build makes the two differ legitimately.
	zip_commit() {
		unzip -p "$1" "$2/build-manifest.json" 2>/dev/null |
			sed -n 's/.*"source_commit"[^"]*"\([0-9a-f]*\)".*/\1/p' | head -1
	}

	# WHAT IS READ IS WHAT IS ENFORCED (V80-01). The first version collected sha,
	# job, matrix, attempt and passed and then refused only on a missing run_id —
	# so a result with no sha, a mix of shas inside one run, an empty job, a
	# passed:false, or eleven of the sixteen matrices all built happily, with
	# every one of those facts printed into the provenance as though it had been
	# checked. Each of them is a condition now.
	#
	# The expected matrices are named here rather than derived from what turned
	# up, because a set derived from the files can never notice a missing one;
	# the check below ties this list to the workflow so it cannot drift silently.
	PROV="$( "$PHP_BIN" -r '
		$dir       = $argv[1];
		$claimed   = isset($argv[2]) ? trim($argv[2]) : "";
		$expected  = explode(",", $argv[3]);
		$free_zip  = isset($argv[4]) ? trim($argv[4]) : "";
		$exp_jobs  = explode(",", $argv[5]);
		$free_head = isset($argv[6]) ? trim($argv[6]) : "";
		sort($expected);
		sort($exp_jobs);

		// BOUND TO WHAT THEY MUST BE, NOT MERELY TO EACH OTHER (V81-03). Sixteen
		// results all naming the same made-up repository agreed perfectly.
		$WANT_REPO     = "rapls/rapls-passkey";
		$WANT_WORKFLOW = "tests";
		$WANT_JOBS     = array("smoke", "concurrency", "release-gate");   // the workflow ids

		$refuse = function ($why) { fwrite(STDERR, "refusing to build: " . $why . "\n"); exit(1); };

		$files = glob($dir . "/*.json");
		sort($files);
		$rows = array();
		$seen = array();
		$jobs = array();
		$agree = array("run_id" => array(), "run_attempt" => array(), "repository" => array(), "sha" => array(), "workflow" => array(), "pro_sha" => array());
		foreach ($files as $f) {
			$base = basename($f);
			if ("PROVENANCE.json" === $base) { continue; }
			$d = json_decode((string) file_get_contents($f), true);
			if (!is_array($d)) { $refuse("{$base} is not JSON"); }
			$ci = isset($d["ci"]) && is_array($d["ci"]) ? $d["ci"] : array();
			$is_status = isset($d["attestation"]) && "job-status" === $d["attestation"];

			// pro_sha may legitimately be "" (a job that did not check Pro out),
			// so it is agreed on but not required to be non-empty.
			$need = array("run_id", "run_attempt", "repository", "sha", "workflow", "job");
			if (!$is_status) { $need[] = "matrix"; }
			foreach ($need as $k) {
				if (!isset($ci[$k]) || "" === trim((string) $ci[$k]) || "unknown" === (string) $ci[$k]) {
					$refuse("{$base} does not say which run produced it ({$k} is missing)\n  (re-download from a run of the workflow that stamps them — see .github/workflows/tests.yml)");
				}
			}
			if (!preg_match("/\A[0-9]+\z/", (string) $ci["run_id"]))      { $refuse("{$base} has a run_id that is not a number"); }
			if (!preg_match("/\A[0-9]+\z/", (string) $ci["run_attempt"])) { $refuse("{$base} has a run_attempt that is not a number"); }
			if (!preg_match("/\A[0-9a-f]{40}\z/", (string) $ci["sha"]))   { $refuse("{$base} has a sha that is not a commit"); }
			if ($WANT_REPO !== (string) $ci["repository"])                { $refuse("{$base} names repository \"" . $ci["repository"] . "\", not {$WANT_REPO}"); }
			if ($WANT_WORKFLOW !== (string) $ci["workflow"])              { $refuse("{$base} names workflow \"" . $ci["workflow"] . "\", not {$WANT_WORKFLOW}"); }
			if (!in_array((string) $ci["job"], $WANT_JOBS, true))         { $refuse("{$base} names job \"" . $ci["job"] . "\", which is not one of " . implode(", ", $WANT_JOBS)); }
			$pro = (string) ($ci["pro_sha"] ?? "");
			if ("" !== $pro && !preg_match("/\A[0-9a-f]{40}\z/", $pro))   { $refuse("{$base} has a pro_sha that is not a commit"); }
			foreach ($agree as $k => $_) { $agree[$k][(string) ($ci[$k] ?? "")] = true; }

			if ($is_status) {
				// HOW THE JOB ENDED (V81-01). A database result says its own
				// scenarios passed; it says nothing about the build, the smoke
				// suite or the reproduction procedure that ran after it in the
				// same job.
				$key = (string) ($d["job_key"] ?? "");
				if ("" === $key)            { $refuse("{$base} is a job attestation with no job_key"); }
				if (isset($jobs[$key]))     { $refuse("two attestations claim to be {$key}"); }
				if ("success" !== (string) ($d["status"] ?? "")) {
					$refuse("job {$key} ended \"" . ($d["status"] ?? "") . "\", not success");
				}
				$jobs[$key] = true;
				// The gate reports every job the API listed; each of those must
				// have succeeded too, so a job outside the two matrices cannot be
				// red while the seven this bundle knows about are green.
				if ("release-gate" === $key) {
					$seen_jobs = isset($d["jobs_seen"]) && is_array($d["jobs_seen"]) ? $d["jobs_seen"] : array();
					if (count($seen_jobs) < 2) { $refuse("the release gate reports fewer than two jobs; it cannot have seen the run"); }
					foreach ($seen_jobs as $name => $conclusion) {
						if ("success" !== (string) $conclusion) { $refuse("the release gate saw \"{$name}\" end as \"{$conclusion}\""); }
					}
				}
				$rows[] = array("file" => $base, "sha256" => hash_file("sha256", $f), "job" => (string) $ci["job"], "job_key" => $key, "attempt" => (string) $ci["run_attempt"], "status" => "success");
				continue;
			}

			// STRICTLY TRUE (V81-01). empty() accepts the STRING "false".
			if (true !== ($d["passed"] ?? null)) { $refuse("{$base} does not record passed:true"); }
			if ((string) $ci["matrix"] !== basename($f, ".json")) {
				$refuse("{$base} is stamped as \"" . $ci["matrix"] . "\", which is not its name");
			}
			if (isset($seen[(string) $ci["matrix"]])) { $refuse("two results claim to be " . $ci["matrix"]); }
			$seen[(string) $ci["matrix"]] = true;
			$rows[] = array(
				"file"    => $base,
				"sha256"  => hash_file("sha256", $f),
				"job"     => (string) $ci["job"],
				"matrix"  => (string) $ci["matrix"],
				"attempt" => (string) $ci["run_attempt"],
				"passed"  => true,
			);
		}
		foreach (array("run_id", "run_attempt", "repository", "sha", "workflow") as $k) {
			if (1 !== count($agree[$k])) {
				$refuse("the results disagree about {$k}: " . implode(", ", array_keys($agree[$k])));
			}
		}
		$pro_shas = array_values(array_filter(array_keys($agree["pro_sha"]), "strlen"));
		if (count($pro_shas) > 1) { $refuse("the results disagree about which Pro commit was tested: " . implode(", ", $pro_shas)); }

		$got = array_keys($seen);
		sort($got);
		if ($got !== $expected) {
			$refuse("the set of results is not the one this workflow produces\n  missing:    " . implode(", ", array_diff($expected, $got))
				. "\n  unexpected: " . implode(", ", array_diff($got, $expected)));
		}
		$got_jobs = array_keys($jobs);
		sort($got_jobs);
		if ($got_jobs !== $exp_jobs) {
			$refuse("the run does not attest that every job succeeded\n  missing:    " . implode(", ", array_diff($exp_jobs, $got_jobs))
				. "\n  unexpected: " . implode(", ", array_diff($got_jobs, $exp_jobs))
				. "\n  (the smoke jobs attest too — a green database matrix is not a green run)");
		}

		$run = (string) array_key_first($agree["run_id"]);
		if ("" !== $claimed && $claimed !== $run) { $refuse("--ci-run says {$claimed}, the results say {$run}"); }

		$run_sha = (string) array_key_first($agree["sha"]);
		if ("" !== $free_zip && $free_zip !== $run_sha) {
			$refuse("CI tested {$run_sha} but the Free ZIP was built from {$free_zip}\n  (rebuild the ZIP at the tested commit, or re-run CI on the commit being shipped)");
		}
		if ("" !== $free_head && $free_head !== $run_sha) {
			$refuse("CI tested {$run_sha} but this Free checkout is at {$free_head}\n  (the bundle is assembled from the working tree; it must be the tested one)");
		}

		echo json_encode(array(
			"run_id"       => $run,
			"run_attempt"  => (string) array_key_first($agree["run_attempt"]),
			"repository"   => (string) array_key_first($agree["repository"]),
			"workflow"     => (string) array_key_first($agree["workflow"]),
			"run_sha"      => $run_sha,
			"tested_pro_commit" => $pro_shas ? $pro_shas[0] : "",
			"jobs"         => $got_jobs,
			"artifacts"    => $rows,
		));
	' "$STAGE/ci-artifacts" "${CI_RUN:-}" "$EXPECTED_MATRICES" "$( zip_commit "$PLUGINS/rapls-passkey.zip" rapls-passkey )" "$EXPECTED_JOBS" "$( cd "$FREE" && git rev-parse HEAD )" )" || exit 1

	get() { printf '%s' "$PROV" | "$PHP_BIN" -r 'echo (string) (json_decode(stream_get_contents(STDIN), true)[$argv[1]] ?? "");' "$1"; }
	RUN_ID="$( get run_id )"
	TESTED_PRO="$( get tested_pro_commit )"
	PRO_ZIP_COMMIT="$( zip_commit "$PLUGINS/rapls-passkey-pro.zip" rapls-passkey-pro )"

	# THREE Pro COMMITS, EACH MEANING SOMETHING DIFFERENT (V80-02).
	#   tested_pro_commit — what CI checked out and ran
	#   pro_zip_commit    — what the shipped package was built from
	#   pro_head          — where the repository stands now
	# They differ legitimately: the digest of a built ZIP is written into
	# update-info.json afterwards, which is a commit CI never saw. What must NOT
	# differ is anything the tests cover, so the two are required to be equal or
	# to differ only in release metadata.
	# EITHER ORDER, BECAUSE BOTH HAPPEN. The usual sequence builds the package,
	# writes its digest into update-info.json, commits that, and pushes — so the
	# commit CI checks out is one AHEAD of the one the package was built from. A
	# re-run of CI on an older commit puts them the other way round. What matters
	# is not which is first but that nothing between them is covered by a test:
	# they must be on one line of history, and the difference must be release
	# metadata only.
	if [ -n "$TESTED_PRO" ] && [ -n "$PRO_ZIP_COMMIT" ] && [ "$TESTED_PRO" != "$PRO_ZIP_COMMIT" ]; then
		if ! ( cd "$PRO" && { git merge-base --is-ancestor "$TESTED_PRO" "$PRO_ZIP_COMMIT" 2>/dev/null || git merge-base --is-ancestor "$PRO_ZIP_COMMIT" "$TESTED_PRO" 2>/dev/null; } ); then
			echo "refusing to build: CI tested Pro at $TESTED_PRO and the package was built from $PRO_ZIP_COMMIT; neither contains the other" >&2
			exit 1
		fi
		# BY CONTENT, NOT BY FILENAME (V81-02). The allowlist named
		# rapls-passkey-pro.php — which is not a version file, it is the code that
		# runs when the plugin boots — so any amount of untested PHP could be
		# added between the tested commit and the built one and still be called
		# "release metadata only". Each changed path is now judged by what changed
		# inside it.
		if ! ( cd "$PRO" && "$PHP_BIN" -r '
			$from = $argv[1];
			$to   = $argv[2];
			$names = array_values(array_filter(explode("\n", (string) shell_exec("git diff --name-only " . escapeshellarg($from) . " " . escapeshellarg($to)))));
			$bad = array();

			// ONE FILE, AND ONLY ITS GENERATED FIELDS (V82-01).
			//
			// The previous rule allowed four kinds of file and judged three of
			// them by their changed lines — which was still too generous in a way
			// that mattered: a .mo was accepted merely because a .po had changed
			// somewhere in the same diff, and a .mo is a compiled catalogue loaded
			// at boot, so "a header line moved in the .po" licensed an arbitrary
			// replacement of what the plugin actually reads. The .po rule itself
			// matched a header-shaped line anywhere in the file, not only in the
			// leading stanza.
			//
			// Rather than tighten three rules, there is one. Between the commit CI
			// tested and the commit the package was built from, the ONLY thing a
			// release does is write the digest of the finished package into
			// update-info.json — the version, the sequence, the readme and every
			// catalogue were settled before the build, in the commit CI ran. So
			// exactly one path may differ, in exactly the fields bin/stamp-release.php
			// generates. Everything else, including the plugin header and anything
			// under languages/, means the shipped tree is not the tested tree.
			$STAMPED = array("version", "release_sequence", "last_updated", "sha256");
			foreach ($names as $path) {
				if ("tools/license-server/update-info.json" !== $path) {
					$bad[] = $path . ": changed between the tested commit and the built one";
					continue;
				}
				$a = json_decode((string) shell_exec("git show " . escapeshellarg($from . ":" . $path)), true);
				$b = json_decode((string) shell_exec("git show " . escapeshellarg($to . ":" . $path)), true);
				if (!is_array($a) || !is_array($b)) {
					$bad[] = $path . ": one of the two versions is not JSON";
					continue;
				}
				foreach (array_unique(array_merge(array_keys($a), array_keys($b))) as $k) {
					$before = $a[$k] ?? null;
					$after  = $b[$k] ?? null;
					if ($before === $after) { continue; }
					if (!in_array($k, $STAMPED, true)) {
						$bad[] = $path . ": field \"" . $k . "\" changed, which the release does not generate";
					}
				}
			}
			if ($bad) {
				fwrite(STDERR, implode("\n", array_map(function ($b) { return "  " . $b; }, $bad)) . "\n");
				exit(1);
			}
		' "$TESTED_PRO" "$PRO_ZIP_COMMIT" ); then
			echo "refusing to build: Pro changed between the tested commit and the built one, in ways a release does not (above)" >&2
			exit 1
		fi
		echo "pro provenance ok: CI tested $TESTED_PRO; the package was built from $PRO_ZIP_COMMIT (update-info.json only)"
	elif [ -n "$TESTED_PRO" ]; then
		echo "pro provenance ok: CI tested and the package was built from $TESTED_PRO"
	else
		echo "refusing to build: no CI result names the Pro commit that was tested" >&2
		exit 1
	fi

	# AND THE TREE THE BUNDLE IS STAGED FROM (V82-02). stage_plugin() copies every
	# tracked file of Pro into rapls-passkey-tests.zip — from the commit since
	# V83-01, and only after the checkout is proved clean —
	# the whole licence server included — and only the tested and built COMMITS
	# were being compared. A change committed after CI finished therefore shipped
	# as source with nothing testing it, and "it is not in the plugin ZIP" is no
	# comfort for tools/license-server/api.php: that file is not distributed to
	# users, it is DEPLOYED. The tree that goes into the bundle has to be the tree
	# that was tested.
	PRO_HEAD="$( cd "$PRO" && git rev-parse HEAD 2>/dev/null || echo '' )"
	if [ -n "$TESTED_PRO" ] && [ "$PRO_HEAD" != "$TESTED_PRO" ]; then
		echo "refusing to build: CI tested Pro at $TESTED_PRO but this Pro checkout is at ${PRO_HEAD:-unknown}" >&2
		echo "  the bundle carries the working tree's source, so it must be the tested one" >&2
		( cd "$PRO" && git diff --name-only "$TESTED_PRO" "$PRO_HEAD" 2>/dev/null | sed 's/^/  changed: /' >&2 ) || true
		exit 1
	fi

	# COUNTED AND NAMED FOR WHAT THEY ARE (V82-05). One field called "results"
	# held the number of every JSON in the directory — results and job
	# attestations together — and the reply built on it said "23 files (16 + 7 +
	# PROVENANCE)" for a directory of 24. Three counts, each of one kind of thing.
	N_RESULTS="$( ls -1 "$STAGE/ci-artifacts" | grep -cE '^(concurrency|integration)-' )"
	N_JOBS="$( ls -1 "$STAGE/ci-artifacts" | grep -c '^job-' )"
	printf '{\n  "run_id": "%s",\n  "run_url": "https://github.com/rapls/rapls-passkey/actions/runs/%s",\n  "run_attempt": "%s",\n  "repository": "%s",\n  "workflow": "%s",\n  "run_sha": "%s",\n  "free_zip_commit": "%s",\n  "tested_pro_commit": "%s",\n  "pro_zip_commit": "%s",\n  "free_head": "%s",\n  "pro_head": "%s",\n  "test_results": %s,\n  "job_attestations": %s,\n  "evidence_files": %s,\n  "jobs": %s,\n  "bundled_at": "%s",\n  "artifacts": %s\n}\n' \
		"$RUN_ID" "$RUN_ID" \
		"$( get run_attempt )" \
		"$( get repository )" \
		"$( get workflow )" \
		"$( get run_sha )" \
		"$( zip_commit "$PLUGINS/rapls-passkey.zip" rapls-passkey )" \
		"$TESTED_PRO" \
		"$PRO_ZIP_COMMIT" \
		"$( cd "$FREE" && git rev-parse HEAD )" \
		"$( cd "$PRO" && git rev-parse HEAD 2>/dev/null || echo unknown )" \
		"$N_RESULTS" "$N_JOBS" "$(( N_RESULTS + N_JOBS ))" \
		"$( printf '%s' "$PROV" | "$PHP_BIN" -r 'echo json_encode(json_decode(stream_get_contents(STDIN), true)["jobs"]);' )" \
		"$( date -u +%Y-%m-%dT%H:%M:%SZ )" \
		"$( printf '%s' "$PROV" | "$PHP_BIN" -r 'echo json_encode(json_decode(stream_get_contents(STDIN), true)["artifacts"], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);' )" \
		> "$STAGE/ci-artifacts/PROVENANCE.json"
	echo "ci provenance ok: run $RUN_ID at $( get run_sha ) — $N_RESULTS results, $N_JOBS job attestations, all present, agreeing and passing"
fi

# Refuse to ship machine-local state or anything shaped like a credential. This
# is a net, not a proof — a dedicated scanner (gitleaks and friends) is the tool
# for that — but it catches the shapes that actually turn up in a tree like this,
# and it fails the build rather than warning.
# fido-mds-roots.pem is the FIDO Alliance's PUBLIC root certificates, shipped on
# purpose; it is named here so the exception is visible rather than a hole in the
# pattern.
BAD="$(find "$STAGE" \( \
	-name 'settings.local.json' -o -name '.env' -o -name '.env.*' \
	-o -name 'rpls-license-data.json' -o -name 'rpls-license-config.php' \
	-o -name 'auth.json' -o -name '.npmrc' -o -name '.netrc' \
	-o -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.p12' -o -name '*.pfx' \
	-o \( -name '*.pem' ! -name 'fido-mds-roots.pem' \) \
	-o -name 'credentials' -o -name 'credentials.json' -o -name '*.kdbx' \
	\) -print)"
if [ -n "$BAD" ]; then
	echo "refusing to build: local or secret-bearing files in the bundle:" >&2
	echo "$BAD" >&2
	exit 1
fi

# Content shapes. Deliberately aimed at SECRETS, not at every long string: a
# 64-character hex value is an Ed25519 PUBLIC key or a SHA-256 digest and appears
# all over this tree legitimately, while 128 hex characters is the size of an
# Ed25519 secret. Anything wider than this needs a real scanner (gitleaks or
# similar); this is the last line of a checklist, not a substitute for one.
PATTERNS=(
	'[0-9a-fA-F]{128,}'
	'-----BEGIN [A-Z ]*PRIVATE KEY-----'
	'gh[pousr]_[A-Za-z0-9]{20,}'
	'github_pat_[A-Za-z0-9_]{20,}'
	'AKIA[0-9A-Z]{16}'
	'aws_secret_access_key'
	'xox[abprs]-[A-Za-z0-9-]{10,}'
	'-----BEGIN PGP PRIVATE KEY BLOCK-----'
)
# Files that legitimately contain long hex or base64: dependency locks (integrity
# hashes), our own manifest of digests, and the CI result JSON. Named here so the
# allowlist is a decision rather than a silent exception.
ALLOW='composer.lock|build-manifest.json|ci-artifacts/|SHA256SUMS|package-lock.json|fido-mds-roots.pem|make-bundle.sh'
FOUND=""
for pattern in "${PATTERNS[@]}"; do
	HITS="$(grep -rlE "$pattern" "$STAGE" 2>/dev/null | grep -vE "$ALLOW" || true)"
	[ -n "$HITS" ] && FOUND="$FOUND$HITS"$'\n'
done
if [ -n "$(printf '%s' "$FOUND" | tr -d '[:space:]')" ]; then
	echo "refusing to build: something in the bundle is shaped like a credential:" >&2
	printf '%s' "$FOUND" >&2
	echo "  (if it is legitimate, add it to ALLOW in bin/make-bundle.sh — deliberately)" >&2
	exit 1
fi

ZIP="$PLUGINS/rapls-passkey-tests.zip"
rm -f "$ZIP"
( cd "$STAGE" && find . -print | LC_ALL=C sort | zip -qX "$ZIP" -@ )

echo "Built: $ZIP"
echo "  files: $(unzip -l "$ZIP" | tail -1 | awk '{print $2}')"
echo "  free zip: $FREE_SHA"
echo "  pro zip:  $PRO_SHA"
