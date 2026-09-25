from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable
import tomllib

SKIP_DIRS = {".git", ".repoproof", "node_modules", "vendor", ".venv", "venv", "dist", "build", "__pycache__"}
MANIFESTS = {
    "pyproject.toml", "requirements.txt", "requirements-dev.txt", "poetry.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock",
}
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)(?::\d+)?(?:[/\s\"'<>]|$)")
SPAWN_PATTERNS = [
    re.compile(r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)\s*\("),
    re.compile(r"\bos\.system\s*\("),
    re.compile(r"\bchild_process\.(?:exec|spawn|fork|execFile)\s*\("),
    re.compile(r"\bexec\.Command(?:Context)?\s*\("),
    re.compile(r"\bCommand::new\s*\("),
]

@dataclass
class Finding:
    section: str
    id: str
    status: str
    statement: str
    evidence: list[str]

def _run(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.strip() or "git command failed")
    return p.stdout

def load_config(repo: Path) -> dict:
    path = repo / "repoproof.toml"
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text(encoding="utf-8"))

def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:4096]

def iter_working_files(repo: Path) -> Iterable[tuple[str, str]]:
    for path in repo.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(repo).parts):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > 2_000_000 or not _is_text(data):
            continue
        yield path.relative_to(repo).as_posix(), data.decode("utf-8", errors="replace")

def iter_ref_files(repo: Path, ref: str) -> Iterable[tuple[str, str]]:
    names = _run(repo, "ls-tree", "-r", "--name-only", ref).splitlines()
    for name in names:
        if any(part in SKIP_DIRS for part in Path(name).parts):
            continue
        p = subprocess.run(["git", "show", f"{ref}:{name}"], cwd=repo, capture_output=True)
        if p.returncode or len(p.stdout) > 2_000_000 or not _is_text(p.stdout):
            continue
        yield name, p.stdout.decode("utf-8", errors="replace")

def snapshot(repo: Path, ref: str | None = None) -> dict:
    files = dict(iter_ref_files(repo, ref)) if ref else dict(iter_working_files(repo))
    domains: dict[str, list[str]] = {}
    spawns: list[str] = []
    for name, text in files.items():
        for match in URL_RE.finditer(text):
            domain = match.group(1).lower().rstrip(".")
            domains.setdefault(domain, [])
            if len(domains[domain]) < 5:
                line = text.count("\n", 0, match.start()) + 1
                domains[domain].append(f"{name}:{line}")
        for pattern in SPAWN_PATTERNS:
            for match in pattern.finditer(text):
                if len(spawns) < 50:
                    line = text.count("\n", 0, match.start()) + 1
                    spawns.append(f"{name}:{line}")
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(files[name].encode(errors="replace"))
        digest.update(b"\0")
    return {
        "fingerprint": digest.hexdigest(),
        "domains": {k: domains[k] for k in sorted(domains)},
        "process_spawns": sorted(set(spawns)),
        "file_count": len(files),
    }

def changed_files(repo: Path, base: str, head: str) -> list[str]:
    out = _run(repo, "diff", "--name-only", base, head)
    return [line for line in out.splitlines() if line]

def _matching_files(repo: Path, include: list[str]) -> list[tuple[str, str]]:
    files = list(iter_working_files(repo))
    if not include:
        return files
    return [(n, t) for n, t in files if any(fnmatch.fnmatch(n, pat) for pat in include)]

def evaluate_claims(repo: Path, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    for item in config.get("claims", []):
        cid = item.get("id", "claim")
        statement = item.get("statement", cid)
        kind = item.get("kind")
        evidence: list[str] = []
        status = "UNPROVEN"
        if kind == "path_exists":
            pattern = item.get("path", "")
            matches = [p.relative_to(repo).as_posix() for p in repo.glob(pattern)]
            status = "VERIFIED" if matches else "CONTRADICTED"
            evidence = matches[:10] or [f"missing: {pattern}"]
        elif kind in {"text_absent", "text_present"}:
            pattern = re.compile(item.get("pattern", ""), re.MULTILINE)
            hits = []
            for name, text in _matching_files(repo, item.get("include", [])):
                for match in pattern.finditer(text):
                    hits.append(f"{name}:{text.count(chr(10), 0, match.start()) + 1}")
                    if len(hits) >= 10:
                        break
                if len(hits) >= 10:
                    break
            if kind == "text_absent":
                status = "VERIFIED" if not hits else "CONTRADICTED"
                evidence = hits or ["pattern absent"]
            else:
                status = "VERIFIED" if hits else "CONTRADICTED"
                evidence = hits or ["pattern not found"]
        findings.append(Finding("CLAIM", cid, status, statement, evidence))
    return findings

def evaluate_boundaries(repo: Path, config: dict, snap: dict | None = None) -> list[Finding]:
    snap = snap or snapshot(repo)
    findings: list[Finding] = []
    boundary = config.get("boundary", {})
    if "network" in boundary:
        network = boundary["network"]
        allowed = {d.lower() for d in network.get("allow", [])}
        actual = set(snap["domains"])
        disallowed = sorted(actual - allowed)
        status = "VERIFIED" if not disallowed else "CONTRADICTED"
        evidence = [f"{d} <- {', '.join(snap['domains'][d][:3])}" for d in disallowed]
        if not evidence:
            evidence = [f"observed domains within allowlist ({len(actual)})"]
        findings.append(Finding("BOUNDARY", "network", status, "Outbound domains stay within declared allowlist", evidence))
    process = boundary.get("process")
    if process is not None and process.get("spawn") is False:
        hits = snap["process_spawns"]
        findings.append(Finding("BOUNDARY", "process.spawn", "VERIFIED" if not hits else "CONTRADICTED", "Process spawning is disabled", hits or ["no known spawn primitives detected"]))
    return findings

def evaluate_invariants(repo: Path, config: dict, base: str, head: str) -> list[Finding]:
    changed = changed_files(repo, base, head)
    findings: list[Finding] = []
    for item in config.get("invariants", []):
        iid = item.get("id", "invariant")
        statement = item.get("statement", iid)
        kind = item.get("kind")
        hits: list[str] = []
        if kind == "paths_unchanged":
            pats = item.get("paths", [])
            hits = [p for p in changed if any(fnmatch.fnmatch(p, pat) for pat in pats)]
        elif kind == "dependencies_unchanged":
            hits = [p for p in changed if Path(p).name in MANIFESTS]
        elif kind == "workflows_unchanged":
            hits = [p for p in changed if p.startswith(".github/workflows/")]
        else:
            findings.append(Finding("INVARIANT", iid, "UNPROVEN", statement, [f"unknown invariant kind: {kind}"]))
            continue
        findings.append(Finding("INVARIANT", iid, "VERIFIED" if not hits else "CONTRADICTED", statement, hits or ["no violating changes"]))
    return findings

def transition(repo: Path, config: dict, base: str, head: str) -> dict:
    before = snapshot(repo, base)
    after = snapshot(repo, head)
    findings = evaluate_invariants(repo, config, base, head)
    allowed = set(config.get("boundary", {}).get("network", {}).get("allow", []))
    new_domains = sorted(set(after["domains"]) - set(before["domains"]))
    disallowed_new = [d for d in new_domains if d not in allowed]
    if "network" in config.get("boundary", {}):
        findings.append(Finding("TRANSITION", "network.expansion", "VERIFIED" if not disallowed_new else "CONTRADICTED", "No undeclared network capability expansion", [f"{d} <- {', '.join(after['domains'][d][:3])}" for d in disallowed_new] or ["no undeclared new domains"]))
    new_spawns = sorted(set(after["process_spawns"]) - set(before["process_spawns"]))
    if config.get("boundary", {}).get("process", {}).get("spawn") is False:
        findings.append(Finding("TRANSITION", "process.expansion", "VERIFIED" if not new_spawns else "CONTRADICTED", "No process-spawn capability expansion", new_spawns or ["no new spawn primitives"]))
    statuses = [f.status for f in findings]
    result = "REVIEW_REQUIRED" if "CONTRADICTED" in statuses or "UNPROVEN" in statuses else "VERIFIED"
    return {
        "base": base, "head": head,
        "changed_files": changed_files(repo, base, head),
        "before": before, "after": after,
        "findings": [asdict(f) for f in findings],
        "result": result,
    }

def current_report(repo: Path, config: dict) -> dict:
    snap = snapshot(repo)
    findings = evaluate_claims(repo, config) + evaluate_boundaries(repo, config, snap)
    statuses = [f.status for f in findings]
    result = "REVIEW_REQUIRED" if "CONTRADICTED" in statuses or "UNPROVEN" in statuses else "VERIFIED"
    return {"snapshot": snap, "findings": [asdict(f) for f in findings], "result": result}

def save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
