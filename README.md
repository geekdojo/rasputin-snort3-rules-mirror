# rasputin-snort3-rules-mirror

A verified, content-addressed mirror of the **Snort3 Community Rules** tarball that
the Rasputin firewall image is built with. Each distinct tarball that Cisco Talos has
published is stored here exactly once, byte for byte. It is verified before it is
added, and it is never changed or removed afterwards.

This README explains why the repository exists, what it does, and how to work on it.
It assumes you have never seen Rasputin before.

- [Background](#background)
- [The problem this solves](#the-problem-this-solves)
- [The principle: break rather than go stale](#the-principle-break-rather-than-go-stale)
- [The mirror contract](#the-mirror-contract)
- [How a new tarball gets into the mirror](#how-a-new-tarball-gets-into-the-mirror)
- [The verification checks, and why each one exists](#the-verification-checks-and-why-each-one-exists)
- [How the firewall's pin gets bumped](#how-the-firewalls-pin-gets-bumped)
- [Why this repository is public](#why-this-repository-is-public)
- [Licensing](#licensing)
- [Running the checks and tests locally](#running-the-checks-and-tests-locally)
- [Triggering a refresh by hand](#triggering-a-refresh-by-hand)
- [When the refresh fails](#when-the-refresh-fails)
- [Out of scope](#out-of-scope)
- [Repository layout](#repository-layout)

## Background

**Rasputin** is Geekdojo's self-hosted platform
([rasputin.geekdojo.com](https://rasputin.geekdojo.com)). One of its parts is a
dedicated **firewall**: an [OpenWrt](https://openwrt.org)-based disk image for small
Intel N100 x86-64 boxes, built in
[`geekdojo/rasputin-openwrt-firewall`](https://github.com/geekdojo/rasputin-openwrt-firewall).
Customers flash the image and later receive updates as new images. Nothing is
installed on the box by hand.

The firewall runs **[Snort 3](https://www.snort.org)**, an open-source intrusion
detection system. Snort inspects traffic and raises an alert when a packet matches a
**rule**, a small pattern such as "an HTTP request for this known exploit path".
Snort without rules detects nothing, so the rules are part of the product.

Rasputin uses the **Snort3 Community Rules**, a free ruleset (about 4,000 rules) that
Cisco's Talos team maintains and publishes as a single tarball at a fixed URL:

```
https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
```

The firewall build **bakes those rules into the image**. During the image build, the
firewall repository's `scripts/fetch-snort-rules.sh` downloads the tarball, checks
its SHA-256 against a value written in that script (the **pin**, `PINNED_SHA`), and
copies the rules into `/etc/snort/rules/`. If the hash does not match, the build
fails. That is called **failing closed**: an unverified ruleset never ships.

## The problem this solves

That URL is a *rolling* URL. Talos republishes the tarball **in place**, about weekly
but on its own schedule, with no announcement. The same URL starts serving different
bytes with a different SHA-256.

A pinned, fail-closed build and a URL that changes under it collide every time:

- The firewall script's comments record **14 hand re-pins** of `PINNED_SHA`. Most
  followed a failed build. Each one meant a human re-downloading and checking the
  new tarball, and a new commit.
- On **2026-09-16** it cost a release. A pre-flight build validated the pinned
  tarball green. About twelve hours later Talos republished. The build of the
  `2026.09.2` stable tag then downloaded the new bytes, the SHA-256 no longer
  matched, and the build failed. Release tags are immutable, so `2026.09.2` could
  not be fixed. The release had to be withdrawn and cut again as `2026.09.3`.

The underlying issue is that one download was doing two jobs at once:

1. **Reproducibility:** *which* bytes does this build use?
2. **Freshness:** are those bytes the *current* rules?

A green pre-flight could not promise that the tag build would use the same bytes,
because the URL is not tied to any particular bytes.

## The principle: break rather than go stale

The obvious fix, "stop failing when upstream moves", is wrong. The fail-closed pin is
currently the only thing that *forces* someone to pick up new rules. If it stopped
failing, rules would quietly get older in every image. For a security appliance,
**breaking loudly is better than going stale silently.**

So the design separates the two jobs and keeps a loud failure for each:

| Job | Where it is enforced | How it fails |
|---|---|---|
| **Reproducibility** | **This mirror.** Every firewall build, the tag build included, downloads the tarball from this mirror at the pinned SHA-256, never from snort.org. A mirror entry never changes, so the pre-flight and the tag build get the same bytes. | A pin that is not in the mirror cannot be downloaded, and the build fails. |
| **Freshness** | **The firewall repository's pre-flight build**, which runs before a release is tagged. It compares upstream's *current* SHA-256 with `PINNED_SHA` and fails when they differ. | The pre-flight fails, and the pin must be bumped before tagging. The failure happens where re-pinning is cheap, not on an immutable tag. |

> **This mirror does not make the firewall's rules fresh on its own.** It only
> guarantees that a given SHA-256 always resolves to the same verified bytes.
> Freshness is enforced by the pre-flight freshness gate in
> `rasputin-openwrt-firewall`, which compares a fact (upstream's SHA-256 against the
> pin), not the age of anything in this repository.

## The mirror contract

The firewall repository depends on exactly this layout. It does not change.

| Item | Value |
|---|---|
| One release per distinct tarball | tagged `sha256-<SHA>` |
| `<SHA>` | the full 64-character, lowercase hex SHA-256 of the tarball |
| Assets per release | exactly one, named `snort3-community-rules.tar.gz` |
| Asset contents | byte-identical to what `https://www.snort.org/downloads/community/snort3-community-rules.tar.gz` served when it was mirrored |
| Download URL | `https://github.com/geekdojo/rasputin-snort3-rules-mirror/releases/download/sha256-<SHA>/snort3-community-rules.tar.gz` |
| Changes | none, ever: no release is edited, overwritten or deleted |

Because the tag *is* the content hash, an entry is **content-addressed**: if you know
the SHA-256 you want, you know the URL, and anything served there can be checked
against the name.

**Immutability** is enforced by GitHub, not just by convention. This repository has
[immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
turned on, so once a release is published its assets cannot be changed or replaced,
and its tag cannot be moved or deleted. The asset is attached when the release is
created, because an immutable release cannot gain an asset later.

### Example: download and check a mirror entry yourself

You need `curl` (a command-line HTTP client) and a SHA-256 tool: `sha256sum` on
Linux, `shasum -a 256` on macOS. Both are preinstalled on most systems.

```sh
# SHA is a placeholder: the 64-character SHA-256 you want. This one is the tarball
# Talos published on 2026-09-16.
SHA=c50913e2153c926fa32bfb897494d1f92ba70d01bfc202e4b22bdbd362c8f9d3

# --fail: exit non-zero on an HTTP error instead of saving the error page.
# --location: follow GitHub's redirect to its download host.
# --output: where to save the file.
curl --fail --location --output snort3-community-rules.tar.gz \
  "https://github.com/geekdojo/rasputin-snort3-rules-mirror/releases/download/sha256-$SHA/snort3-community-rules.tar.gz"

# Print the file's SHA-256. It must equal $SHA. (On macOS: shasum -a 256 <file>)
sha256sum snort3-community-rules.tar.gz
```

## How a new tarball gets into the mirror

The GitHub Actions workflow [`.github/workflows/rasputin-refresh.yml`](.github/workflows/rasputin-refresh.yml)
does it. There is no pull request and no human click. It runs:

- **daily on a schedule**;
- **by hand** (see [Triggering a refresh by hand](#triggering-a-refresh-by-hand));
- **on every pull request, as a dry run**: every check runs against the real,
  current upstream tarball, even if that tarball is already mirrored, and the log
  says what a real run would publish. Nothing is published.

Each run has two jobs:

1. **`verify`** (read-only permissions). It downloads the upstream tarball and works
   out its SHA-256. If `sha256-<SHA>` is already mirrored and intact, it stops and
   says so: nothing to do. Otherwise it runs every check below. If any check fails,
   the run fails and names the check. If all checks pass, it hands the verified
   bytes to the next job.
2. **`publish`** (the only job allowed to write). It runs only when `verify` passed
   and this is not a dry run. It checks again that the bytes hash to the verified
   SHA-256 and that the entry still does not exist. It then creates the release
   `sha256-<SHA>` with the tarball as its single asset. Finally it checks the result
   from the outside: the release must be published, immutable, and have one asset
   whose GitHub-computed digest is the SHA-256, and the public download URL must
   serve bytes with that SHA-256.

The logic lives in shell scripts under [`scripts/`](scripts), not inline in the
workflow YAML, so the same code can be tested and run on your own machine.

## The verification checks, and why each one exists

Nothing is published unless **all** of these pass.

### Check 1: two separate HTTPS downloads hash identical

`scripts/fetch-upstream.sh` downloads the tarball twice, with two separate `curl`
processes, so two separate TLS connections. It refuses anything but HTTPS, including
after redirects. Both files must have the same SHA-256.

**Why:** one download proves only that *something* arrived. Two independent
downloads that agree rule out a truncated or corrupted transfer, and they expose a
server that hands out different bytes to different requests. Before this repository
existed, the hand re-pins followed the same rule: download again and compare,
rather than trusting the hash a failed build printed.

If Talos happens to republish between the two downloads, this check fails. That is
correct, and the next run picks up the new tarball.

### Check 2: the layout is exactly the five known members

`scripts/verify-tarball.sh` (logic in `check_layout` in `scripts/lib.sh`) requires a
valid gzip tarball containing exactly these files, each once and each a regular file,
under one top-level directory:

```
snort3-community-rules/
snort3-community-rules/snort3-community.rules   the rules
snort3-community-rules/sid-msg.map              rule id -> message map
snort3-community-rules/VRT-License.txt          licence
snort3-community-rules/LICENSE                  licence (GPLv2)
snort3-community-rules/AUTHORS                  credits
```

An extra file, a missing file, a symlink or hard link, a nested directory, a `./`
prefix or a renamed top directory all fail.

**Why:** the firewall build unpacks this directory straight into the image's
`/etc/snort/`. A changed layout means either Talos changed its packaging, which a
human should look at before it reaches customers, or this is not the tarball we
think it is. A symlink or an unexpected path in an archive that is unpacked into a
root filesystem is a classic way to write files where they do not belong.

### Check 3: the rule count is sane

The number of **active** rules must be between **3,600 and 8,000**. Active means
lines starting with `alert`, `drop`, `block` or `reject`; commented-out rules do not
count. The count uses the same expression as the firewall's fetch script:
`grep -cE '^(alert|drop|block|reject)'`.

**Why these numbers:** every firewall pin since June 2026 whose rule count was
recorded had **4,017** active rules.

- The **floor, 3,600**, is about 90% of that. It leaves room for Talos to retire a
  few hundred rules in one release without a false alarm. It still catches the
  failures that matter: an empty or truncated rules file, a ruleset with most rules
  commented out, or a gutted ruleset. All of those would parse cleanly and silently
  ship a firewall that detects almost nothing.
- The **ceiling, 8,000**, is about double. The Community ruleset does not double
  overnight. A sudden jump like that more likely means a different ruleset is being
  served at the URL, and a human should look.

If Talos legitimately moves outside these bounds, the refresh fails loudly, a human
confirms the change, and the bounds in `scripts/lib.sh` are updated in a pull request.

### Check 4: the rules load under Snort in the latest stable firewall image

This is the check that matters most. It answers: "will Snort, exactly as it runs on a
customer's firewall, accept every one of these rules?"

1. `scripts/fetch-firewall-image.sh` downloads the A/B disk image (`*-ab.img.gz`)
   from the **latest stable (non-prerelease) release** of
   `rasputin-openwrt-firewall`. It verifies the image's CMS signature against the
   public Rasputin root CA in [`trust/rasputin-root-ca.pem`](trust/rasputin-root-ca.pem)
   (the same certificate as <https://rasputin.geekdojo.com/rasputin-root-ca.pem>)
   **before** unpacking anything, because the next steps run the image's programs as
   root.
2. `scripts/extract-firewall-root.sh` finds the GPT partition named `rootfs-0` (slot
   A's root filesystem, a squashfs), copies it out and unpacks it with `unsquashfs`.
3. `scripts/snort-check.sh`:
   - applies the firewall's own Snort settings: the `set snort.*` lines from
     `/etc/uci-defaults/99-rasputin` *inside that image*, which a real box applies on
     first boot. **UCI** is OpenWrt's configuration system. These settings switch
     Snort to Rasputin's generated configuration: the tap interface, `HOME_NET`,
     alert-only mode, and Rasputin's extra Lua config;
   - mounts `/proc`, `/dev` and a `tmpfs` `/tmp` into the unpacked root, then uses
     `chroot` (run a program with a directory as its `/`) to run the image's own
     `snort-mgr -v check`;
   - runs that check twice: once with an **empty** community rules file (the
     baseline) and once with the candidate rules. It requires that Snort **validated
     the configuration**, **loaded the candidate file**, and loaded **exactly as many
     more rules than the baseline as the file has active rules**.

Several details are there because simpler versions were tried and do not work.
`snort-mgr check` can exit 0 **without checking the rules at all** in three ways, and
check 4 fails on each:

- **Without `-v`**, `snort-mgr check` skips the rules and passes even with a broken
  rule in place. Only `-v` loads `/etc/snort/rules/*.rules`.
- **With `snort.snort.manual=1`** (the package's default), `check` returns 0 before
  running Snort. Check 4 requires `manual` to read `0` after applying the image's
  settings.
- **With an empty ruleset** (or only commented-out rules), Snort still validates
  cleanly, because it loads the image's own built-in rules. Check 4 requires the
  candidate to contain active rules.

Two more details:
- A bare `snort -c /etc/snort/snort.lua -R <rules> -T` fails with thousands of
  undefined-variable errors, because the variables Rasputin's configuration needs
  are generated by `snort-mgr`, not defined in the stock `snort.lua`.
- An exit code of 0 only proves Snort rejected nothing it read. The loaded-count
  comparison proves it actually read every rule. For example, Snort keeps only one
  of two rules with the same id and still exits 0. The functional test covers that
  case.

**Keep this check in step with the firewall's.** The firewall build runs the same
kind of check on every image it builds (`scripts/rasputin-snort-rules-check.sh` in
`rasputin-openwrt-firewall`): the same image-supplied UCI settings, the same
`snort-mgr -v check`, and the same three no-op failures above. If the two drift
apart, this mirror could accept a tarball that the firewall build then rejects.
Change both together. The one deliberate difference is that this check is
**stricter**: it requires Snort to load *exactly* as many rules as the file has
active rules (the firewall's check requires at least as many), and it also requires
Snort's "Loading …snort3-community.rules" and "successfully validated" lines. So
this mirror can only refuse a tarball the firewall would accept, loudly, and never
the reverse.

**Why this check exists:** the firewall's first ruleset was *not* the Community
Rules. It was ET Open, fetched from a URL that said `snort-3.0.0`, whose rules still
used Snort 2 keyword placement. On the first hardware bring-up, Snort 3 rejected them
with **212,249 parse errors** and stopped (`FATAL: see prior 212249 errors`). A human
approving a pull request would not have caught that, and a hash check cannot. Only
loading the rules into the real Snort does. Testing against the latest *stable*
image means the rules are proven against the Snort version, configuration and
defaults that customers actually run.

### Checks on the mirror itself

- **Already mirrored?** `scripts/mirror-status.sh` does not only ask "does a release
  exist?". It requires the release to be published, immutable, and to carry exactly
  one asset with the right name, whose GitHub-computed SHA-256 digest equals the
  tag. Anything else, including an API error or a bare tag with no release, fails
  the run. An error can never be mistaken for "absent" (which would lead to a publish
  attempt) or for "mirrored" (which would lead to doing nothing).
- **After publishing**, the same status check runs again, and the public download URL
  is fetched and hashed.

### Tests

Hand-written verification code on a security appliance's supply chain has to be
tested itself. [`.github/workflows/rasputin-ci.yml`](.github/workflows/rasputin-ci.yml)
runs on every pull request and every push to `main`:

- **`shellcheck`**, a static analyser for shell scripts, on every script.
- **Unit tests**, [`tests/unit.sh`](tests/unit.sh). They build fixture tarballs and
  replace `curl` and `gh` with fakes, so they never touch the network. They cover the
  happy path and every negative case: extra, missing, duplicated, symlinked and
  hard-linked members; wrong top directory; not gzip; truncated; counts just outside
  and exactly on each bound; commented-out rules; mismatched double downloads; every
  way a mirror entry can be broken; dry runs never publishing; and refusing to
  publish bytes that changed after verification.
- **A functional test**, [`tests/functional-snort.sh`](tests/functional-snort.sh). It
  runs check 4 against the real Snort in the latest stable firewall image. Good rules
  (the ruleset shipped in that image, and a small hand-written set) must pass. Broken
  rules must fail, and fail for the right reason: an invented keyword, the same
  invented keyword hidden among all 4,017 real rules, an unbalanced parenthesis,
  Snort 2 keyword placement (the ET Open failure), an undefined variable, an invalid
  regular expression, and a duplicate rule id that Snort silently drops. The three
  ways `snort-mgr check` can exit 0 without checking anything must also fail: a copy
  of the check with `-v` removed, `manual=1` in the image's settings, and an empty
  or comments-only rules file.

## How the firewall's pin gets bumped

The pin lives in one place: `PINNED_SHA` in `scripts/fetch-snort-rules.sh` in
[`rasputin-openwrt-firewall`](https://github.com/geekdojo/rasputin-openwrt-firewall).

When Talos republishes:

1. This repository's daily refresh verifies the new tarball and adds
   `sha256-<new SHA>` to the mirror, with no human involved.
2. The next firewall **pre-flight** build fails its freshness gate, because upstream's
   SHA-256 no longer equals `PINNED_SHA`.
3. `PINNED_SHA` is bumped to the new SHA-256 **as part of the release-prep change**
   that the maintainer already reviews and merges. The build then downloads that
   entry from this mirror.

Two things are **deliberately absent**:

- **No "refresh" pull request per upstream change.** It would become a rubber stamp:
  approved without reading, costing time and protecting nothing. A human reading a
  diff of 4,000 rules cannot spot a compromised upstream, because we pin whatever
  Talos serves. The automated checks above are the real gate.
- **No bot pushes to the firewall repository.** Nothing in this repository has, or
  needs, write access anywhere except its own releases.

## Why this repository is public

Nothing here is secret:

- the tarball is freely downloadable from snort.org;
- the SHA-256 pins are in the public firewall repository's fetch script;
- the rules themselves are inside every public firewall image.

A private mirror would add risk, not remove it. The public firewall repository's
builds would need a cross-repository credential just to download a public file, and
anyone outside Geekdojo who wants to rebuild the firewall image from source could
not.

## Licensing

- **The rules** belong to Cisco Talos and the Snort community. They are distributed
  under the licences that ship **inside the tarball**: `LICENSE` (GNU GPL v2),
  `VRT-License.txt`, and the credits in `AUTHORS`. This mirror redistributes the
  tarball unmodified, byte for byte, so those files always travel with the rules.
- **Everything else in this repository** (scripts, tests, workflows, documentation)
  is licensed under the **GNU Affero General Public License v3.0**, the same licence
  as `rasputin-openwrt-firewall`. See [`LICENSE`](LICENSE).

## Running the checks and tests locally

The scripts target **Linux** (Ubuntu 24.04, the same as CI). They rely on GNU `tar`,
and check 4 needs root for `mount` and `chroot`. On macOS or Windows, run them inside
a Linux container, as shown below.

### What you need

- **Docker** ([Docker Desktop](https://www.docker.com/products/docker-desktop/) on
  macOS or Windows). Check with `docker version`.
- **A clone of this repository.** Run every command below from its top-level
  directory.
- **For the functional test and the full check only:** a GitHub token, so the scripts
  can download the firewall image with the GitHub CLI (`gh`). If you have `gh`
  installed and logged in on your machine, `gh auth token` prints one. Any token that
  can read public repositories works.

Tested on an x86-64 machine. The firewall image contains x86-64 programs, so on an
ARM machine (for example an Apple Silicon Mac), add `--platform linux/amd64` after
`docker run`. Docker then runs the container under emulation, which is slower; that
setup has not been tested.

### Unit tests (no network, no token, no root)

```sh
docker run --rm -v "$PWD":/repo -w /repo ubuntu:24.04 \
  bash -c './scripts/install-deps-ubuntu.sh && tests/unit.sh'
```

- `docker run --rm`: start a container and delete it when it exits.
- `-v "$PWD":/repo -w /repo`: make your clone visible inside the container at
  `/repo`, and start there.
- `ubuntu:24.04`: the container image, the same Ubuntu version CI uses.
- `scripts/install-deps-ubuntu.sh`: installs the tools the scripts need (`curl`,
  `jq`, `openssl`, `sfdisk`, `unsquashfs`, `gh`, `shellcheck`). It skips anything
  already installed.
- `tests/unit.sh`: prints `ok` or `FAIL` for each case, and exits 0 only if every
  case passed.

To run the linter as well, replace `tests/unit.sh` with
`shellcheck -x scripts/*.sh tests/*.sh && tests/unit.sh`.

### Functional test (real Snort; needs a token and a privileged container)

```sh
export GH_TOKEN="$(gh auth token)"
docker run --rm --privileged -e GH_TOKEN -v "$PWD":/repo -w /repo ubuntu:24.04 \
  bash -c './scripts/install-deps-ubuntu.sh && tests/functional-snort.sh'
```

- `export GH_TOKEN=...`: put your token in an environment variable, which `gh` reads.
- `--privileged`: allows `mount` and `chroot` inside the container. Check 4 needs
  them. Only use it with code you have read.
- `-e GH_TOKEN`: pass that variable into the container without writing the token on
  the command line.

This downloads about 60 MB, then takes under a minute. It ends with
`functional tests: N passed, 0 failed`.

### The full check against today's upstream tarball (never publishes)

```sh
export GH_TOKEN="$(gh auth token)"
docker run --rm --privileged -e GH_TOKEN -e DRY_RUN=1 -v "$PWD":/repo -w /repo ubuntu:24.04 \
  bash -c './scripts/install-deps-ubuntu.sh && scripts/verify-upstream.sh /tmp/work && scripts/publish.sh /tmp/work'
```

- `-e DRY_RUN=1`: run every check even if the tarball is already mirrored, and make
  `publish.sh` report what it *would* publish instead of publishing. Without write
  access to this repository a real publish would fail anyway, but always pass
  `DRY_RUN=1` locally.
- `scripts/verify-upstream.sh /tmp/work`: runs checks 1 to 4, using `/tmp/work`
  inside the container as scratch space. It ends with `ALL CHECKS PASSED for
  sha256-<SHA>` or names the failed check.
- `scripts/publish.sh /tmp/work`: in dry-run mode, prints the release, asset and URL
  a real run would create.

## Triggering a refresh by hand

You need write access to this repository.

**In the browser:** open the repository's **Actions** tab, choose
**rasputin-refresh** on the left, click **Run workflow**, leave **dry_run**
unticked for a real refresh (tick it to only verify), and click the green **Run
workflow** button.

**With the GitHub CLI** ([install `gh`](https://cli.github.com), then `gh auth login`):

```sh
# Real refresh: publishes if upstream has a tarball that is not mirrored yet.
gh workflow run rasputin-refresh.yml --repo geekdojo/rasputin-snort3-rules-mirror

# Verify only; publishes nothing.
gh workflow run rasputin-refresh.yml --repo geekdojo/rasputin-snort3-rules-mirror -f dry_run=true

# Watch the run you just started. Pick it from the list, and gh follows it until it ends.
gh run watch --repo geekdojo/rasputin-snort3-rules-mirror
```

A run that finds the tarball already mirrored succeeds, with the log line
`already mirrored as sha256-<SHA>; nothing to do`.

## When the refresh fails

A failed run publishes nothing, and the mirror stays as it was. GitHub emails a
failed scheduled run to the person who last changed the workflow's schedule. Open the
failed run: the error annotation at the top names the check, and the log above it
shows the details.

| What failed | What it usually means | What to do |
|---|---|---|
| **Check 1**: `the two independent downloads differ` | Talos republished between the two downloads, or a transfer was corrupted. | Run the workflow again by hand. If it keeps failing, the server is serving inconsistent bytes: do not publish; investigate. |
| **Check 1**: `download ... failed` | snort.org is down or unreachable. | Wait, then run it again. The existing mirror entries still work. |
| **Check 2**: `layout: ...` | Talos changed the tarball's packaging, or something else is being served. | Download the tarball yourself and look at what changed. If the change is legitimate, update the firewall's fetch script to handle it *first*, then update `EXPECTED_MEMBERS` in `scripts/lib.sh` and its unit tests in a pull request. |
| **Check 3**: `count: ... below the floor` or `above the ceiling` | The ruleset shrank or grew sharply. | Look at the rules file. A truncated, empty or mostly commented-out file is a real problem: do not change the bounds to make it pass. If Talos really did retire or add that many rules, change the bounds in `scripts/lib.sh`, with the evidence, in a pull request. |
| **Check 4**: `snort-mgr -v check rejected` | At least one rule does not load under the Snort that customers run. | The log lists Snort's `ERROR:` lines with file line numbers. This tarball must not ship. Wait for Talos to publish a fixed tarball; if it persists, raise it with Talos. |
| **Check 4**: `exited 0 without loading any rules`, or `snort.snort.manual is ...` | The latest firewall image's Snort setup changed, so `snort-mgr check` no longer checks rules the way it did. | Nothing was verified. Compare that release's `99-rasputin` and Snort package with the previous one, update this check and the firewall's together, and run `tests/functional-snort.sh`. |
| **Check 4**: `Snort loaded N rules ... but the file has M` | Snort accepted the file but silently skipped some rules (for example duplicate rule ids). | Find the skipped rules. Do not publish until it is understood. |
| **Check 4**: `the harness is broken, not the rules` | The firewall image failed the check even with no community rules at all, so the image or this repository's scripts changed. | Run `tests/functional-snort.sh` locally, and compare the latest firewall release's `99-rasputin` and Snort package with the previous one. |
| **Firewall image**: `signature verification FAILED` | The downloaded image does not verify against the Rasputin root CA. | Treat it as a security incident, not a flaky download. Do not use the image; tell the firewall maintainer. |
| **Mirror status**: `exists but is not intact`, or `has no published release` | A mirror entry or tag is not in the state this repository creates. | **Never delete or overwrite a mirror entry.** A human must look at it. |

Scheduled workflows have one more failure mode, and this one is **silent**: GitHub
automatically disables a public repository's scheduled workflows after 60 days
without repository activity. If the Actions tab shows **rasputin-refresh** as
disabled, enable it again and run it by hand. Even then nothing unsafe happens:
the firewall's pre-flight gate still fails when upstream moves, and a new pin that
is not in the mirror cannot be downloaded, so that build fails loudly as well.

## Out of scope

This repository only concerns **which rules an image is built with**. Once a firewall
is flashed, its rules age until the box installs a newer image. Keeping the rules on
a *deployed* firewall fresh is a separate effort.

## Repository layout

```
.github/workflows/
  rasputin-refresh.yml       daily / manual / pull-request dry-run refresh
  rasputin-ci.yml            shellcheck, unit tests, functional test
scripts/
  lib.sh                     contract constants and the offline checks (sourced)
  fetch-upstream.sh          check 1: two downloads, hashes compared
  verify-tarball.sh          checks 2 and 3: layout and rule count
  mirror-status.sh           is sha256-<SHA> already mirrored, and intact?
  fetch-firewall-image.sh    latest stable firewall image, signature verified
  extract-firewall-root.sh   unpack rootfs-0 from the image
  snort-check.sh             check 4: snort-mgr -v check in a chroot
  verify-upstream.sh         runs all of the above in order
  publish.sh                 create the immutable release and verify it from outside
  install-deps-ubuntu.sh     install the tools the scripts need
tests/
  unit.sh                    offline unit tests with fixtures and fakes
  functional-snort.sh        real Snort: good rules pass, broken rules fail
trust/
  rasputin-root-ca.pem       public Rasputin root CA, for the firewall image signature
```
