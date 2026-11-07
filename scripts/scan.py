#!/usr/bin/env python3
"""Deterministic security scanner for upstream app updates.

Compares two git refs inside one repository (read-only `git -C <repo>`
plumbing, never a checkout) and reports anything "new" in the NEW ref that
was not already present in the OLD ref:

  1. NEW NETWORK HOSTS     hosts matching https?://<host> or wss?://<host>
                           in the NEW tree that do not appear anywhere in
                           the OLD tree (set difference over text files,
                           so pre-existing hosts are never re-flagged)
  2. ANDROID PERMISSIONS   android:name values of <uses-permission> and
                           <uses-permission-sdk-23> in every
                           AndroidManifest.xml and in added lines of
                           *.patch files; new ones not present in OLD
  3. TRACKERS              Exodus-Privacy tracker code/network signature
                           matches, flagged only when the match count
                           increased compared with OLD
  4. DEPENDENCIES          added/removed lines in build files: build.gradle,
                           *.gradle, *.gradle.kts, libs.versions.toml,
                           .gitmodules, package.json, bun.lock, Cargo.toml,
                           Cargo.lock, CMakeLists.txt (FetchContent or
                           ExternalProject lines only), apktool.yml
  5. BINARIES              files added or modified with extensions
                           .so/.jar/.aar/.dex/.dll/.exe/.bin/.apk/.zip or
                           which git reports as binary
  6. SENSITIVE PATHS       changed files matching profile-sensitive globs
  7. BUILDABILITY          apktool only: CRITICAL when AndroidManifest.xml
                           or apktool.yml is missing from NEW
  8. INFORMATIONAL         commit count/log, changed-file count and (for
                           android-patchset) whether upstream-commit moved;
                           informational only, never flags

Exit codes: 0 = clean, 10 = flagged (needs review), 2 = usage/internal
error.  Python 3.12+, standard library only.  Works with bare, non-bare
and --filter=blob:none clones (partial-clone blobs are materialized by
ensure_blobs_present()); no network access is made for local test repos.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field

EXIT_CLEAN = 0     # no finding, safe to build
EXIT_FLAGGED = 10  # needs human review, do not build
EXIT_ERROR = 2     # usage or internal error

SNIPPET_MAX = 300          # chars kept of any offending line
SNIPPET_SAFE_MIN = 120     # never show lines shorter than this when they fit
MAX_BLOB_BYTES = 8 << 20   # treat larger files as opaque
MAX_ITEMS_1 = 60           # max report entries for hosts
MAX_ITEMS_2 = 40           # max report entries for other sections
MAX_LOG_LINES = 20         # subjects shown in the informational section

PROFILES = ("android-patchset", "apktool")

# glob list is checked with fullmatch (see glob_to_regex)
PROFILE_GLOBS: dict[str, list[str]] = {
    "android-patchset": [
        "src/fork/helpers/update/**",
        "src/fork/helpers/network/**",
        "src/fork/helpers/plugins/**",
        "src/fork/helpers/badges/**",
        "src/fork/helpers/push/**",
        "src/fork/helpers/translate/**",
        "src/fork/InuConfig.kt",
        "patches/**/*network*",
        "patches/**/*update*",
        ".github/**",
        "scripts/**",
        "upstream-commit",
    ],
    "apktool": [
        "AndroidManifest.xml",
        "apktool.yml",
        "original/**",
        "smali*/**/net/**",
        "smali*/**/http*/**",
    ],
}

GREP_TEXT_EXTS = {  # never treat such blobs as corpus text
    ".so", ".jar", ".aar", ".dex", ".dll", ".exe", ".bin", ".apk", ".zip",
    ".aab", ".7z", ".gz", ".bz2", ".xz", ".zst", ".lz4", ".whl", ".pack",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tga",
    ".mp3", ".mp4", ".ogg", ".opus", ".wav", ".flac", ".webm", ".mkv",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pdf", ".db", ".keystore", ".jks", ".p12", ".class", ".pyc",
    ".wasm", ".rlib", ".rmeta", ".obj", ".a", ".lib", ".pdb",
    ".icu", ".dat", ".box", ".train",
}

FLAGGED_BINARY_SUFFIXES = (
    ".so", ".jar", ".aar", ".dex", ".dll", ".exe", ".bin", ".apk", ".zip")

DEP_BASENAMES = {"build.gradle", "libs.versions.toml", ".gitmodules",
                 "package.json", "bun.lock", "Cargo.toml", "Cargo.lock",
                 "apktool.yml"}
DEP_SUFFIXES = (".gradle", ".gradle.kts")

IGNORED_HOSTS = {
    "example.com", "example.org", "example.net", "localhost", "127.0.0.1",
    "www.w3.org", "schemas.android.com",
}
IGNORED_HOST_SUFFIXES = (".example", ".localhost")

# scheme://host part only; query strings and URL paths are never matched
HOST_RE = re.compile(r"\b(?:https?|wss?)://([A-Za-z0-9._~%:@-]+)")

PERM_ELEMENT_RE = re.compile(
    r"<uses-permission(?:-sdk-23)?\b[^<>]*?android:name\s*=\s*([\"'])"
    r"(android\.[A-Za-z0-9_.]+)\1")

CMAKE_DEP_RE = re.compile(r"\b(?:FetchContent|ExternalProject)\b")

STATUS_NAME = {"A": "added", "M": "modified", "D": "deleted"}


class ScanError(Exception):
    """Internal error -> exit code 2."""


# ---------------------------------------------------------------------------
# git plumbing (read-only, `-C <repo>`, no checkouts)
# ---------------------------------------------------------------------------


def git_oneshot(repo: str, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", repo, *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def git(repo: str, *args: str) -> bytes:
    proc = git_oneshot(repo, list(args))
    if proc.returncode != 0:
        raise ScanError("`git %s` failed: %s" % (
            " ".join(args), proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout


def git_text(repo: str, *args: str) -> str:
    return git(repo, *args).decode("utf-8", "replace")


def resolve_ref(repo: str, ref: str) -> str:
    proc = git_oneshot(repo, ["rev-parse", "--verify", "--quiet",
                              ref + "^{commit}"])
    if proc.returncode != 0 or not proc.stdout:
        raise ScanError("ref %r is not present in %s" % (ref, repo))
    return proc.stdout.decode().strip()


def ls_tree(repo: str, rev: str) -> dict[str, str]:
    """path -> blob oid map of the whole tree at rev."""
    files: dict[str, str] = {}
    out = git(repo, "ls-tree", "-r", "-z", rev).decode("utf-8", "replace")
    for rec in out.split("\0"):
        if not rec:
            continue
        meta, _, path = rec.partition("\t")
        try:
            _mode, otype, oid = meta.split()
        except ValueError:
            continue
        if otype == "blob" and path:
            files[path] = oid
    return files


def diff_name_status(repo: str, old: str, new: str) -> dict[str, str]:
    """path -> first status letter for changes old..new (no rename folding)."""
    out = git(repo, "diff", "--no-renames", "-z", "--name-status",
              old, new).decode("utf-8", "replace")
    statuses: dict[str, str] = {}
    toks = [t for t in out.split("\0") if t]
    i = 0
    while i < len(toks):
        status, path = toks[i], toks[i + 1]
        i += 2
        if status[0] in "RC":
            i += 1  # second path of a rename/copy (defensive)
        statuses[path] = status[0]
    return statuses


def diff_numstat(repo: str, old: str, new: str) -> dict[str, bool]:
    """path -> True when git reports the file as binary ('-' numstat).

    `git diff -z --numstat` records are NUL-terminated with the three
    fields (added, deleted, path) tab-separated inside each record.
    """
    out = git(repo, "diff", "--no-renames", "-z", "--numstat",
              old, new).decode("utf-8", "replace")
    result: dict[str, bool] = {}
    for record in out.split("\0"):
        if not record:
            continue
        fields = record.split("\t")
        if len(fields) < 3:
            continue
        if fields[0] == "-" or fields[1] == "-":
            result[fields[-1]] = True
    return result


def diff_side_lines(repo: str, old: str, new: str, path: str,
                    side: str) -> list[str]:
    """Changed lines of the old..new diff of one file: the added ('+')
    lines when side='new', the removed ('-') lines when side='old'."""
    prefix = "+" if side == "new" else "-"
    skip = prefix * 3
    out = git_text(repo, "diff", "--no-color", "--no-renames", "-U0",
                   old, new, "--", path)
    lines = []
    for line in out.splitlines():
        if line.startswith(prefix) and not line.startswith(skip):
            lines.append(line[1:])
    return lines


def blob_text(repo: str, rev: str, path: str) -> bytes:
    proc = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise ScanError("`git show %s:%s` failed: %s" % (
            rev, path, proc.stderr.decode("utf-8", "replace").strip()))
    return proc.stdout


def ls_tree_blob_sizes(repo: str, rev: str) -> dict[str, int]:
    """blob oid -> committed size (used to skip huge blobs)."""
    sizes: dict[str, int] = {}
    out = git(repo, "ls-tree", "-r", "-l", "-z", rev).decode("utf-8", "replace")
    for rec in out.split("\0"):
        if not rec:
            continue
        meta, _, _path = rec.partition("\t")
        parts = meta.split()
        if len(parts) < 4:
            continue
        _mode, _otype, oid, size = parts[:4]
        if oid in sizes:
            continue
        try:
            sizes[oid] = int(size)
        except (TypeError, ValueError):
            continue
    return sizes


def missing_blob_oids(repo: str, oids: list[str]) -> list[str]:
    """oid list, filtered to those absent from the local object store."""
    if not oids:
        return []
    payload = "".join(oid + "\n" for oid in oids).encode()
    proc = subprocess.run(["git", "-C", repo, "cat-file", "--batch-check"],
                          input=payload, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    missing = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] == "missing":
            missing.append(parts[0])
    return missing


def ensure_blobs_present(repo: str, oids: list[str]) -> None:
    """Materialize blobs when scanning a --filter=blob:none clone."""
    missing = missing_blob_oids(repo, oids)
    if not missing:
        return
    remotes = git_text(repo, "remote").split()
    if remotes:
        # --refetch ignores any partial-clone filter for this one fetch and
        # pulls the whole pictures for the already-known refs.
        git_oneshot(repo, ["fetch", "--refetch", remotes[0]])
    still = missing_blob_oids(repo, oids)
    if still:
        raise ScanError(
            "%d blob(s) needed for the scan are missing from this clone "
            "(partial clone?). Run `git fetch --refetch origin` inside the "
            "clone, or re-clone without --filter." % len(still))


def path_split_dirs(path: str) -> list[str]:
    return path.split("/")[:-1]


def file_basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def file_ext(path: str) -> str:
    name = file_basename(path)
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1].lower()


# ---------------------------------------------------------------------------
# Corpus: text content of one tree, keyed by path
# ---------------------------------------------------------------------------


class Tree:
    """Loaded text corpus of one revision plus repo/rev bookkeeping."""

    def __init__(self, repo: str, rev: str, files: dict[str, str]):
        self.repo = repo
        self.rev = rev
        self.files = files
        self.sizes = ls_tree_blob_sizes(repo, rev)
        self.raw: dict[str, bytes] = {}
        self.text: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        wanted = sorted(
            {oid for path, oid in self.files.items()
             if file_ext(path) not in GREP_TEXT_EXTS
             and 0 <= self.sizes.get(oid, 1 << 40) <= MAX_BLOB_BYTES})
        payload = "".join(oid + "\n" for oid in wanted).encode()
        proc = subprocess.run(["git", "-C", self.repo, "cat-file", "--batch"],
                              input=payload, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise ScanError("git cat-file --batch failed: %s"
                            % proc.stderr.decode("utf-8", "replace")[:400])
        data = proc.stdout
        for _ in wanted:
            line_end = data.find(b"\n", 0)
            header = data[:line_end].decode("ascii", "replace").split()
            data = data[line_end + 1:]
            if len(header) < 3 or header[2] == "missing":
                continue
            _hdr_oid, _otype, size = header[0], header[1], int(header[2])
            self.raw[_hdr_oid] = data[:size]
            data = data[size + 1:]
        for path, oid in self.files.items():
            raw = self.raw.get(oid)
            if raw is None:
                continue
            if b"\x00" in raw[:8192] or b"\x00" in raw[-8192:]:
                continue  # git-declared text but actually binary-ish
            self.text[path] = raw.decode("utf-8", "replace")

    def has_text(self, path: str) -> bool:
        return path in self.text

    def text_of(self, path: str) -> str:
        return self.text.get(path, "")


def load_tree(repo: str, rev: str) -> Tree:
    files = ls_tree(repo, rev)
    ensure_blobs_present(repo, list(files.values()))
    return Tree(repo, rev, files)


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class Section:
    title: str
    is_critical: bool = False
    items: list[str] = field(default_factory=list)

    def add(self, item: str) -> None:
        self.items.append(item)

    def empty(self) -> bool:
        return not self.items

    def markdown(self) -> str:
        title = self.title + (" (CRITICAL)" if self.is_critical else "")
        return "## " + title + "\n" + "\n".join(self.items)

    def json(self) -> dict:
        return {"title": self.title, "critical": self.is_critical,
                "items": self.items}


def snippet(text: str) -> str:
    """One offending line, truncated to SNIPPET_MAX characters."""
    if len(text) > SNIPPET_MAX:
        return text[:SNIPPET_MAX] + " ...[truncated]"
    return text


@dataclass
class ScanResult:
    repo: str
    profile: str
    old_ref: str
    new_ref: str
    sections: list[Section]
    verdict: str

    @property
    def flagged(self) -> bool:
        return self.verdict.startswith("NEEDS REVIEW")

    def json_data(self) -> dict:
        return {
            "verdict": self.verdict,
            "flagged": self.flagged,
            "repo": self.repo,
            "profile": self.profile,
            "old_ref": self.old_ref,
            "new_ref": self.new_ref,
            "sections": [s.json() for s in self.sections if not s.empty()],
        }

    def markdown_report(self) -> str:
        lines = [
            "# Upstream update scan",
            "",
            self.verdict_line(),
            "",
            "- repository scanned: `%s` (profile `%s`)" % (self.repo,
                                                           self.profile),
            "- **old** (audited) ref: `%s`" % self.old_ref,
            "- **new** ref: `%s`" % self.new_ref,
            "",
        ]

        body_parts = []
        for sec in self.sections:
            if not sec.empty():
                body_parts.append(sec.markdown())
                body_parts.append("")
        md = "\n".join(lines)
        if body_parts:
            md += "\n".join(body_parts) + "\n"
        footnote = "\n---\n\nEach check lists file paths and the offending\n" \
                   "lines (truncated to 300 chars per line).\n"
        return md + footnote

    def verdict_line(self) -> str:
        if self.verdict == "CLEAN":
            return "**Verdict: CLEAN** - no new signals; safe to build " \
                   "and publish."
        return "**Verdict: %s**" % self.verdict


# ---------------------------------------------------------------------------
# Check helpers
# ---------------------------------------------------------------------------


def normalize_host(authority: str) -> str:
    if "@" in authority:            # user:pass@host
        authority = authority.rsplit("@", 1)[1]
    host = authority.split(":", 1)[0].strip(".").lower()
    return host


def host_ignored(host: str) -> bool:
    if host in IGNORED_HOSTS:
        return True
    return any(host.endswith(suffix) for suffix in IGNORED_HOST_SUFFIXES)


def collect_hosts(tree: Tree) -> tuple[set[str],
                                       dict[str, list[tuple[str, str]]]]:
    """(hosts, examples): every host text-corpus wide, with up to 3
    (path, matched-line) pairs kept as example per host."""
    hosts: set[str] = set()
    examples: dict[str, list[tuple[str, str]]] = {}
    for path in sorted(tree.text):
        content = tree.text[path]
        if not content:
            continue
        for m in HOST_RE.finditer(content):
            host = normalize_host(m.group(1))
            if not host or host_ignored(host):
                continue
            hosts.add(host)
            bucket = examples.setdefault(host, [])
            if len(bucket) < 3:
                start = content.rfind("\n", 0, m.start()) + 1
                end = content.find("\n", m.end())
                line_end = end if end != -1 else len(content)
                line = content[start:line_end]
                bucket.append((path, snippet(line)))
    return hosts, examples


def manifest_permissions(text: str) -> set[str]:
    """android:name of <uses-permission> / <uses-permission-sdk-23>."""
    out: set[str] = set()
    for match in PERM_ELEMENT_RE.finditer(text):
        name = match.group(2)
        if name.startswith("android.permission.") or not name.endswith(".*"):
            out.add(name)
    return out


def build_tracker_matcher(trackers: dict) -> tuple[re.Pattern | None,
                                                   dict[str, tuple[str, str]],
                                                   list[str]]:
    """One combined alternation regex across all tracker signatures.

    groups map: group-name -> (tracker name, 'code'|'network')
    Warns for unusable network_signature regexes.
    """
    groups: dict[str, tuple[str, str]] = {}
    alternates: list[str] = []
    warns: list[str] = []
    for tid, entry in trackers.items():
        name = str(entry.get("name") or tid)
        code_sig = (entry.get("code_signature") or "").strip()
        parts = [p.strip() for p in code_sig.split("|") if p.strip()]
        if parts:
            dotted = "|".join(re.escape(p) for p in parts)
            slash = "|".join(re.escape(
                "L" + p.rstrip(".") + "/") for p in parts)
            gname = "c" + re.sub(r"[^0-9A-Za-z_]", "_", tid)
            alternates.append(f"(?P<{gname}>{dotted}|{slash})")
            groups[gname] = (name, "code")
        net_sig = (entry.get("network_signature") or "").strip()
        if net_sig:
            try:
                re.compile(net_sig)
            except re.error:
                warns.append("tracker %r network_signature %-40.40r "
                             "does not compile" % (name, net_sig))
                continue
            gname = "n" + re.sub(r"[^0-9A-Za-z_]", "_", tid)
            alternates.append(f"(?P<{gname}>{net_sig})")
            groups[gname] = (name, "network")
    if not alternates:
        return None, groups, warns
    return re.compile("|".join(alternates)), groups, warns


def count_tracker_hits(pattern: re.Pattern, groups: dict[str, tuple[str, str]],
                       tree: Tree) -> tuple[dict[tuple[str, str], int],
                                            dict[tuple[str, str], set[str]]]:
    """occurrence counts + matched-file examples per (tracker, kind)."""
    counts: dict[tuple[str, str], int] = {}
    files_seen: dict[tuple[str, str], set[str]] = {}
    for path in sorted(tree.text):
        content = tree.text[path]
        if not content:
            continue
        for m in pattern.finditer(content):
            gname = m.lastgroup
            if not gname or gname not in groups:
                continue
            tracker_name, kind = groups[gname]
            key = (tracker_name, kind)
            counts[key] = counts.get(key, 0) + 1
            files_seen.setdefault(key, set()).add(path)
    return counts, files_seen


def glob_to_regex(glob_expr: str) -> re.Pattern[str]:
    """Path glob -> regex.  '**' spans zero or more whole directories
    (plus any trailing file), '*' stays within one path segment, '?'
    matches one char."""
    all_segs = glob_expr.split("/")
    parts: list[str] = []
    for i, seg in enumerate(all_segs):
        if seg == "**":
            is_last = i == len(all_segs) - 1
            parts.append("(?:[^/]+/)*[^/]+" if is_last else "(?:[^/]+/)*")
            continue
        text = "".join(re.escape(ch) for ch in seg)
        text = text.replace(re.escape("**"), ".*")  # '**' inside a segment
        text = text.replace(re.escape("*"), "[^/]*")
        text = text.replace(re.escape("?"), "[^/]")
        parts.append(text)
    return re.compile("/".join(parts))


def is_sensitive_path(path: str, blob: list[re.Pattern]) -> bool:
    return any(p.fullmatch(path) for p in blob)


def is_dep_file(path: str) -> bool:
    name = file_basename(path)
    lower = name.lower()
    if name in DEP_BASENAMES or lower in DEP_BASENAMES:
        return True
    return any(lower.endswith(sfx) for sfx in DEP_SUFFIXES)


def is_flagged_binary(path: str) -> bool:
    return file_basename(path).lower().endswith(FLAGGED_BINARY_SUFFIXES)


def top_level_dirs(files: dict[str, str]) -> set[str]:
    tops: set[str] = set()
    for p in files:
        if "/" in p:
            tops.add(p.split("/", 1)[0])
    return tops


# ---------------------------------------------------------------------------
# The scan: sequence of §1..§8 with verdict assembly
# ---------------------------------------------------------------------------


def run_scan(repo: str, old_ref: str, new_ref: str, profile: str,
             tracker_file: str) -> ScanResult:
    old_rev = resolve_ref(repo, old_ref)
    new_rev = resolve_ref(repo, new_ref)

    with open(tracker_file, "r", encoding="utf-8") as fh:
        tracker_data = json.load(fh)
    if not isinstance(tracker_data, dict) or not isinstance(
            tracker_data.get("trackers"), dict):
        raise ScanError("tracker file must be JSON with a 'trackers' object")

    old_tree = load_tree(repo, old_rev)
    new_tree = load_tree(repo, new_rev)
    changes = diff_name_status(repo, old_rev, new_rev)
    git_binaries = diff_numstat(repo, old_rev, new_rev)

    sections: list[Section] = []
    sec_info = Section("8. INFORMATIONAL")  # never produces a verdict reason

    # ---- 1. network hosts -----------------------------------------------------
    old_hosts, _ = collect_hosts(old_tree)
    new_hosts, new_examples = collect_hosts(new_tree)
    fresh_hosts = sorted(new_hosts - old_hosts)[:MAX_ITEMS_1]
    sec_hosts = Section("1. NEW NETWORK HOSTS")
    for host in fresh_hosts:
        for path, line in new_examples.get(host, [])[:1]:
            kind = " (smali const-string)" if path.endswith(".smali") else ""
            sec_hosts.add("- host `%s`%s, e.g. in `%s`:\n"
                          "  `%s`" % (host, kind, path, line.replace("`", "'")))
    if sec_hosts.empty() and len(new_hosts - old_hosts) > MAX_ITEMS_1:
        sec_hosts.add("(first %d of %d new hosts listed)"
                      % (MAX_ITEMS_1, len(new_hosts - old_hosts)))
    if not sec_hosts.empty():
        sections.append(sec_hosts)

    # ---- 2. Android permissions -----------------------------------------------
    sec_perms = Section("2. ANDROID PERMISSIONS")
    old_perms: set[str] = set()
    new_perms: set[str] = set()
    for path in sorted(new_tree.text):
        if path.endswith("AndroidManifest.xml"):
            new_perms |= manifest_permissions(new_tree.text_of(path))
    for path in sorted(old_tree.text):
        if path.endswith("AndroidManifest.xml"):
            old_perms |= manifest_permissions(old_tree.text_of(path))
    # added lines of changed *.patch files
    patch_perm_hits: list[tuple[str, set[str]]] = []
    changed_patches = sorted(
        p for p, st in changes.items() if p.endswith(".patch") and st in "AM")
    for path in changed_patches:
        for delta_line in diff_side_lines(repo, old_rev, new_rev, path,
                                          side="new"):
            perms = manifest_permissions(delta_line)
            if perms:
                patch_perm_hits.append((path, perms))
                new_perms |= perms
    # baseline: every *.patch file in OLD counts as already present
    for path in sorted(p for p in old_tree.files if p.endswith(".patch")):
        old_perms |= manifest_permissions(old_tree.text_of(path))
    added_perms = sorted(new_perms - old_perms)
    if profile == "apktool":
        hits = sum(new_tree.text_of(p).count("android.permission.INTERNET")
                   for p in new_tree.text)
        if hits:
            sec_perms.is_critical = True
            sec_perms.add(
                "`android.permission.INTERNET` occurs %d time(s) in the NEW "
                "tree. A decompiled keyboard gaining network access must "
                "always be reviewed by a human." % hits)
            files_with_internet = [
                p for p in sorted(new_tree.text)
                if "android.permission.INTERNET" in new_tree.text[p]][:5]
            for p in files_with_internet:
                sec_perms.add("  - `%s`" % p)
    if added_perms:
        if not sec_perms.is_critical:
            sec_perms.add(
                "New permission(s), not present in the OLD ref: %s"
                % ", ".join("`%s`" % p for p in added_perms))
        for path, perms in patch_perm_hits:
            if perms & set(added_perms):
                sec_perms.add("- in `%s` (patch file)" % path)
        for path in sorted(new_tree.text):
            if path.endswith("AndroidManifest.xml"):
                found = manifest_permissions(new_tree.text_of(path)) & set(added_perms)
                if found:
                    sec_perms.add("- in `%s`" % path)
    if not sec_perms.empty():
        sections.append(sec_perms)

    # ---- 3. trackers ------------------------------------------------------------
    sec_track = Section("3. TRACKERS")
    pattern, groups, warns = build_tracker_matcher(tracker_data["trackers"])
    if pattern is not None:
        old_counts, _ = count_tracker_hits(pattern, groups, old_tree)
        new_counts, file_hits = count_tracker_hits(pattern, groups, new_tree)
        for key in sorted(new_counts):
            hits_old = old_counts.get(key, 0)
            hits_new = new_counts[key]
            if hits_new > hits_old:
                name, kind = key
                sec_track.add(
                    "- %s (%s): %d -> %d match(es)%s"
                    % (name, kind, hits_old, hits_new,
                       ", in: " + ", ".join("`%s`" % p for p in
                                            sorted(file_hits.get(key, set()))[:3])
                       if file_hits.get(key) else ""))
    if not sec_track.empty():
        sections.append(sec_track)
    for warn in warns:
        sec_info.add("[warn] %s" % warn)

    # ---- 4. dependencies --------------------------------------------------------
    sec_deps = Section("4. DEPENDENCIES")
    for path in sorted(p for p, st in changes.items()
                       if st in "AMD" and is_dep_file(p)):
        removed = diff_side_lines(repo, old_rev, new_rev, path, side="old")
        added = diff_side_lines(repo, old_rev, new_rev, path, side="new")
        if path.endswith("CMakeLists.txt"):
            added = [l for l in added if CMAKE_DEP_RE.search(l)]
            removed = [l for l in removed if CMAKE_DEP_RE.search(l)]
        if not added and not removed:
            continue
        sec_deps.add("`%s` (%s)" % (path, STATUS_NAME.get(changes[path], "changed")))
        for line in added[:10]:
            sec_deps.add("  + `%s`" % snippet(line))
        for line in removed[:10]:
            sec_deps.add("  - `%s`" % snippet(line))
        if len(added) + len(removed) > 20:
            sec_deps.add("  (%d more lines omitted)"
                         % (len(added) + len(removed) - 20))
    if not sec_deps.empty():
        sections.append(sec_deps)

    # ---- 5. binaries ------------------------------------------------------------
    sec_bins = Section("5. BINARIES")
    flagged_bins = []
    if profile == "apktool":
        old_tops = top_level_dirs(old_tree.files)
        new_tops = top_level_dirs(new_tree.files)
        fresh_tops = sorted(new_tops - old_tops)
        if fresh_tops:
            sec_bins.add("New top-level directories (not present in OLD):")
            for top in fresh_tops:
                sec_bins.add("  - `%s/`" % top)
    for path, st in sorted(changes.items()):
        if st not in "AM":
            continue
        is_bin = is_flagged_binary(path) or git_binaries.get(path, False)
        if profile == "apktool" and path.startswith(("res/", "assets/")):
            if path.startswith("lib/") and path.endswith(".so"):
                flagged_bins.append(path)
            else:
                sec_info.add("[info] `%s` changed under res/ or assets/ "
                             "(routine for apktool re-decompilation)" % path)
        elif profile == "apktool" and path.startswith("lib/") and path.endswith(".so"):
            flagged_bins.append(path)
        elif is_bin:
            flagged_bins.append(path)
    if flagged_bins:
        sec_bins.add("Binary files added or modified:")
        for p in flagged_bins[:MAX_ITEMS_2]:
            sec_bins.add("  - `%s`" % p)
    if not sec_bins.empty():
        sections.append(sec_bins)

    # ---- 6. sensitive paths ------------------------------------------------------
    sec_sensitive = Section("6. SENSITIVE PATHS")
    sensitive = [glob_to_regex(g) for g in PROFILE_GLOBS[profile]]
    for path, st in sorted(changes.items()):
        if is_sensitive_path(path, sensitive):
            sec_sensitive.add("`%s` changed (%s)" % (path, STATUS_NAME.get(st, st)))
    if not sec_sensitive.empty():
        sections.append(sec_sensitive)

    # ---- 7. buildability (apktool) -------------------------------------------------
    sec_build = Section("7. BUILDABILITY (apktool)")
    if profile == "apktool":
        missing = [n for n in ("AndroidManifest.xml", "apktool.yml")
                   if n not in new_tree.files]
        if missing:
            sec_build.is_critical = True
            sec_build.add("CRITICAL: `%s` missing from the NEW tree; apktool "
                          "cannot build this version (the decompiled project "
                          "was damaged or a wizard is not configured?)."
                          % "`, `".join(missing))
    if not sec_build.empty():
        sections.append(sec_build)

    # ---- 8. informational ----------------------------------------------------------
    commit_count = git_text(repo, "rev-list", "--count",
                            f"{old_rev}..{new_rev}").strip()
    sec_info.add("Commits between `%s` and `%s`: %s"
                 % (old_ref, new_ref, commit_count))
    subjects = [s for s in git_text(
        repo, "log", "--format=%s", f"{old_rev}..{new_rev}").splitlines() if s]
    if subjects:
        sec_info.add("Commit subjects (first %d):" % MAX_LOG_LINES)
        for s in subjects[:MAX_LOG_LINES]:
            sec_info.add("  - " + s)
        if len(subjects) > MAX_LOG_LINES:
            sec_info.add("  - ... (%d more)" % (len(subjects) - MAX_LOG_LINES))
    sec_info.add("Files changed between `%s` and `%s`: %d"
                 % (old_ref, new_ref, len(changes)))
    if profile == "android-patchset":
        old_up = (blob_text(repo, old_rev, "upstream-commit")
                  if "upstream-commit" in old_tree.files else b"")
        new_up = (blob_text(repo, new_rev, "upstream-commit")
                  if "upstream-commit" in new_tree.files else b"")
        if old_up and new_up:
            sec_info.add(
                "upstream-commit: %s -> %s%s"
                % (old_up.decode("ascii", "ignore").strip(),
                   new_up.decode("ascii", "ignore").strip(),
                   " (changed)" if old_up != new_up else " (unchanged)"))
    sections.append(sec_info)

    # ---- verdict --------------------------------------------------------------------
    reasons, critical = [], False
    for sec in sections:
        if sec.empty() or sec.title.startswith("8."):
            continue
        label = re.sub(r"^\d+\.\s*", "", sec.title)
        label = re.sub(r"\s*\(apktool\)$", "", label)
        prefix = sec.is_critical and "critical: " or ""
        if sec.is_critical:
            critical = True
        reasons.append(prefix + label)
    if not reasons:
        verdict = "CLEAN"
    elif all(r.startswith("critical:") for r in reasons):
        verdict = "NEEDS REVIEW — %s" % "; ".join(reasons)
    else:
        verdict = "NEEDS REVIEW — %s" % "; ".join(reasons)
    return ScanResult(
        repo=repo, profile=profile, old_ref=old_ref, new_ref=new_ref,
        sections=sections, verdict=verdict)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a NEW git ref against an audited OLD ref.")
    parser.add_argument("--repo", required=True,
                        help="path to (a clone of) the git repository")
    parser.add_argument("--old", required=True,
                        help="audited ref: tag or commit SHA")
    parser.add_argument("--new", required=True,
                        help="candidate ref: tag or commit SHA")
    parser.add_argument("--profile", required=True, choices=PROFILES,
                        help="sensitivity profile to apply")
    parser.add_argument("--trackers", required=True,
                        help="path to data/exodus-trackers.json")
    parser.add_argument("--report", required=True,
                        help="markdown report output path")
    parser.add_argument("--json", dest="json_path", metavar="OUT_JSON",
                        help="optional JSON report output path")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        result = run_scan(args.repo, args.old, args.new, args.profile,
                          args.trackers)
    except ScanError as exc:
        print("scan error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except (OSError, ValueError, KeyError) as exc:
        print("scan error: unexpected %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr)
        return EXIT_ERROR

    report_md = result.markdown_report()
    with open(args.report, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(result.json_data(), fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    if result.flagged:
        print(result.verdict, file=sys.stderr)
        return EXIT_FLAGGED
    print(result.verdict)
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
