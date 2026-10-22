"""Deterministic detection of LLM, agent and MCP applications.

Tags a checkout, and the files in it, as an LLM application when its own
code imports a model SDK, an agent framework, an MCP server SDK or a vector
store, when a manifest declares one directly, or when it ships prompt-template
files. The tag gates the LLM application review checklist (OWASP LLM Top 10
categories) and the ``llm-integration`` review surface: a repository with no
signal is ``not_applicable``, citing this result.

This is a CANDIDATE GENERATOR and a fact, never a finding
(docs/deterministic-inferential-mix.md): it says *where* LLM code is, so the
review knows which files to read against the checklist. It reads files only;
nothing in the target is imported, built or run, and no git command runs in
it (an audited repository's git config is untrusted).

Signals come from two places:
- **source imports** (Python, JavaScript/TypeScript, Go, Java/Kotlin, Rust),
  with ``file:line`` evidence. These also tag the files that use the library.
- **direct manifest declarations** (``requirements*.txt``, ``pyproject.toml``,
  ``package.json``, ``go.mod``, ``pom.xml``, ``Cargo.toml``), never
  lockfiles, because a lockfile also lists libraries pulled in transitively.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path

from traust_engine.portfolio import parsers as manifest_parsers
from traust_engine.portfolio.graph import parse_gomod

KINDS = ("model-sdk", "agent-framework", "mcp-server", "vector-store", "prompt-template")

# (kind, library) per import root. Python roots are top-level module names;
# JS roots are package names (scoped packages included); Go and Java roots are
# path prefixes; Rust roots are crate names.
PYTHON = {
    "openai": ("model-sdk", "openai"),
    "anthropic": ("model-sdk", "anthropic"),
    "google.genai": ("model-sdk", "google-genai"),
    "google.generativeai": ("model-sdk", "google-generativeai"),
    "vertexai": ("model-sdk", "vertexai"),
    "mistralai": ("model-sdk", "mistralai"),
    "cohere": ("model-sdk", "cohere"),
    "groq": ("model-sdk", "groq"),
    "ollama": ("model-sdk", "ollama"),
    "litellm": ("model-sdk", "litellm"),
    "transformers": ("model-sdk", "transformers"),
    "vllm": ("model-sdk", "vllm"),
    "llama_cpp": ("model-sdk", "llama-cpp-python"),
    "langchain": ("agent-framework", "langchain"),
    "langchain_core": ("agent-framework", "langchain"),
    "langchain_community": ("agent-framework", "langchain"),
    "langchain_openai": ("agent-framework", "langchain"),
    "langchain_anthropic": ("agent-framework", "langchain"),
    "langgraph": ("agent-framework", "langgraph"),
    "llama_index": ("agent-framework", "llama-index"),
    "crewai": ("agent-framework", "crewai"),
    "autogen": ("agent-framework", "autogen"),
    "autogen_agentchat": ("agent-framework", "autogen"),
    "semantic_kernel": ("agent-framework", "semantic-kernel"),
    "haystack": ("agent-framework", "haystack"),
    "dspy": ("agent-framework", "dspy"),
    "smolagents": ("agent-framework", "smolagents"),
    "pydantic_ai": ("agent-framework", "pydantic-ai"),
    "mcp": ("mcp-server", "mcp"),
    "fastmcp": ("mcp-server", "fastmcp"),
    "chromadb": ("vector-store", "chromadb"),
    "pinecone": ("vector-store", "pinecone"),
    "qdrant_client": ("vector-store", "qdrant"),
    "weaviate": ("vector-store", "weaviate"),
    "pymilvus": ("vector-store", "milvus"),
    "faiss": ("vector-store", "faiss"),
    "lancedb": ("vector-store", "lancedb"),
    "pgvector": ("vector-store", "pgvector"),
}
NPM = {
    "openai": ("model-sdk", "openai"),
    "@anthropic-ai/sdk": ("model-sdk", "anthropic"),
    "@google/genai": ("model-sdk", "google-genai"),
    "@google/generative-ai": ("model-sdk", "google-generativeai"),
    "@mistralai/mistralai": ("model-sdk", "mistralai"),
    "cohere-ai": ("model-sdk", "cohere"),
    "groq-sdk": ("model-sdk", "groq"),
    "ollama": ("model-sdk", "ollama"),
    "ai": ("model-sdk", "vercel-ai-sdk"),
    "@ai-sdk/": ("model-sdk", "vercel-ai-sdk"),
    "langchain": ("agent-framework", "langchain"),
    "@langchain/": ("agent-framework", "langchain"),
    "llamaindex": ("agent-framework", "llama-index"),
    "@mastra/": ("agent-framework", "mastra"),
    "@modelcontextprotocol/sdk": ("mcp-server", "mcp"),
    "@pinecone-database/pinecone": ("vector-store", "pinecone"),
    "chromadb": ("vector-store", "chromadb"),
    "@qdrant/js-client-rest": ("vector-store", "qdrant"),
    "weaviate-client": ("vector-store", "weaviate"),
}
GO = {
    "github.com/openai/openai-go": ("model-sdk", "openai"),
    "github.com/sashabaranov/go-openai": ("model-sdk", "openai"),
    "github.com/anthropics/anthropic-sdk-go": ("model-sdk", "anthropic"),
    "google.golang.org/genai": ("model-sdk", "google-genai"),
    "github.com/google/generative-ai-go": ("model-sdk", "google-generativeai"),
    "github.com/ollama/ollama/api": ("model-sdk", "ollama"),
    "github.com/tmc/langchaingo": ("agent-framework", "langchaingo"),
    "github.com/cloudwego/eino": ("agent-framework", "eino"),
    "github.com/mark3labs/mcp-go": ("mcp-server", "mcp"),
    "github.com/modelcontextprotocol/go-sdk": ("mcp-server", "mcp"),
    "github.com/qdrant/go-client": ("vector-store", "qdrant"),
    "github.com/milvus-io/milvus-sdk-go": ("vector-store", "milvus"),
    "github.com/weaviate/weaviate-go-client": ("vector-store", "weaviate"),
    "github.com/pinecone-io/go-pinecone": ("vector-store", "pinecone"),
}
JAVA = {
    "dev.langchain4j": ("agent-framework", "langchain4j"),
    "org.springframework.ai": ("agent-framework", "spring-ai"),
    "com.openai": ("model-sdk", "openai"),
    "com.anthropic": ("model-sdk", "anthropic"),
    "io.modelcontextprotocol": ("mcp-server", "mcp"),
}
RUST = {
    "async_openai": ("model-sdk", "openai"),
    "ollama_rs": ("model-sdk", "ollama"),
    "rig": ("agent-framework", "rig"),
    "rmcp": ("mcp-server", "mcp"),
    "qdrant_client": ("vector-store", "qdrant"),
}
# Manifest package names that differ from the import root.
DECLARED_ALIASES = {
    "PyPI": {
        "google-genai": "google.genai",
        "google-generativeai": "google.generativeai",
        "google-cloud-aiplatform": "vertexai",
        "llama-cpp-python": "llama_cpp",
        "llama-index": "llama_index",
        "llama-index-core": "llama_index",
        "langchain-core": "langchain_core",
        "langchain-community": "langchain_community",
        "langchain-openai": "langchain_openai",
        "langchain-anthropic": "langchain_anthropic",
        "pyautogen": "autogen",
        "autogen-agentchat": "autogen_agentchat",
        "semantic-kernel": "semantic_kernel",
        "haystack-ai": "haystack",
        "dspy-ai": "dspy",
        "pydantic-ai": "pydantic_ai",
        "qdrant-client": "qdrant_client",
        "weaviate-client": "weaviate",
        "pinecone-client": "pinecone",
        "faiss-cpu": "faiss",
        "faiss-gpu": "faiss",
    },
    "crates.io": {"async-openai": "async_openai", "ollama-rs": "ollama_rs"},
}

SOURCE_SUFFIXES = {
    ".py": "python",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "js",
    ".tsx": "js",
    ".mts": "js",
    ".cts": "js",
    ".go": "go",
    ".java": "java",
    ".kt": "java",
    ".rs": "rust",
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "site-packages",
    "__pycache__",
    "dist",
    "build",
    ".tox",
}
MAX_FILE_BYTES = 1_000_000

_PY_IMPORT = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))"
)
_JS_IMPORT = re.compile(
    r"""(?:\bfrom\s*['"]([^'"]+)['"]|\bimport\s*['"]([^'"]+)['"]|\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)|\bimport\s*\(\s*['"]([^'"]+)['"]\s*\))"""
)
_GO_IMPORT_LINE = re.compile(r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"([^"]+)"')
_JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)")
_RUST_USE = re.compile(r"^\s*(?:pub\s+)?(?:use|extern\s+crate)\s+([A-Za-z_]\w*)")

# Prompt-template files: dedicated extensions, or text templates under a
# directory named prompt(s).
PROMPT_SUFFIXES = (".prompt", ".prompty", ".prompt.yaml", ".prompt.yml", ".prompt.md")
PROMPT_DIR_SUFFIXES = (
    ".txt",
    ".md",
    ".j2",
    ".jinja",
    ".jinja2",
    ".mustache",
    ".hbs",
    ".tmpl",
    ".yaml",
    ".yml",
)


def _python_match(module: str):
    parts = module.split(".")
    for n in range(len(parts), 0, -1):
        hit = PYTHON.get(".".join(parts[:n]))
        if hit:
            return hit
    return None


def _npm_match(spec: str):
    if spec.startswith((".", "/")):
        return None
    if spec in NPM:
        return NPM[spec]
    for prefix, hit in NPM.items():
        if prefix.endswith("/") and spec.startswith(prefix):
            return hit
    # a subpath import ("openai/resources") belongs to its package
    parts = spec.split("/")
    pkg = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    return NPM.get(pkg)


def _prefix_match(path: str, table: dict):
    for prefix, hit in table.items():
        if path == prefix or path.startswith(prefix + "/") or path.startswith(prefix + "."):
            return hit
    return None


def _imports(lang: str, text: str):
    """Yield (line number, matched (kind, library)) for every LLM import."""
    in_go_block = False
    for lineno, line in enumerate(text.splitlines(), 1):
        hits = []
        if lang == "python":
            m = _PY_IMPORT.match(line)
            if m:
                mods = [m.group(1)] if m.group(1) else [s.strip() for s in m.group(2).split(",")]
                hits = [_python_match(mod) for mod in mods]
        elif lang == "js":
            for m in _JS_IMPORT.finditer(line):
                hits.append(_npm_match(next(g for g in m.groups() if g)))
        elif lang == "go":
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_go_block = True
                continue
            if in_go_block and stripped.startswith(")"):
                in_go_block = False
                continue
            if in_go_block or stripped.startswith("import "):
                m = _GO_IMPORT_LINE.match(line)
                if m:
                    hits.append(_prefix_match(m.group(1), GO))
        elif lang == "java":
            m = _JAVA_IMPORT.match(line)
            if m:
                hits.append(_prefix_match(m.group(1), JAVA))
        elif lang == "rust":
            m = _RUST_USE.match(line)
            if m:
                hits.append(RUST.get(m.group(1)))
        for hit in hits:
            if hit:
                yield lineno, hit


_PY_LOCAL = re.compile(r"^\s*(?:from\s+(\.*[\w.]*)\s+import\s+([\w*, ()]+)|import\s+([\w.]+))")
_JS_LOCAL = re.compile(
    r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)['"](\.{1,2}/[^'"]+)['"]"""
)
_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")


def _local_targets(lang: str, rel: str, text: str, known: set[str]) -> set[str]:
    """In-repo files a source file imports (Python modules, relative JS/TS)."""
    here = Path(rel).parent
    out: set[str] = set()
    if lang == "python":
        for line in text.splitlines():
            m = _PY_LOCAL.match(line)
            if not m:
                continue
            if m.group(3):
                mods = [m.group(3)]
            else:
                base, names = m.group(1), m.group(2)
                dots = len(base) - len(base.lstrip("."))
                root = here
                for _ in range(max(dots - 1, 0)):
                    root = root.parent
                stem = base.lstrip(".")
                prefix = (
                    (root.as_posix() + "/" if dots and root.as_posix() != "." else "")
                    if dots
                    else ""
                )
                mods = [prefix.replace("/", ".") + stem] if stem else []
                # "from pkg import module" may name submodules
                for n in re.split(r"[,\s()]+", names):
                    if n and n != "*":
                        mods.append(f"{prefix.replace('/', '.')}{stem + '.' if stem else ''}{n}")
            for mod in mods:
                path = mod.strip(".").replace(".", "/")
                for cand in (f"{path}.py", f"{path}/__init__.py"):
                    if cand in known:
                        out.add(cand)
    elif lang == "js":
        for m in _JS_LOCAL.finditer(text):
            target = (here / m.group(1)).as_posix()
            parts = []
            for seg in target.split("/"):
                if seg == "..":
                    if parts:
                        parts.pop()
                elif seg not in (".", ""):
                    parts.append(seg)
            base = "/".join(parts)
            stem = re.sub(r"\.(js|mjs|cjs)$", "", base)
            for cand in [
                base,
                *(stem + e for e in _JS_EXTS),
                *(f"{base}/index{e}" for e in _JS_EXTS),
            ]:
                if cand in known:
                    out.add(cand)
    out.discard(rel)
    return out


def _is_prompt_template(rel: str) -> bool:
    low = rel.lower()
    if low.endswith(PROMPT_SUFFIXES):
        return True
    parts = Path(low).parts
    return any(p in ("prompt", "prompts") for p in parts[:-1]) and low.endswith(PROMPT_DIR_SUFFIXES)


def _declared(repo: Path, rel: str, text: str):
    """(kind, library) for each LLM library a manifest declares directly."""
    name = Path(rel).name
    hits = []
    if name == "go.mod":
        _module, deps = parse_gomod(text)
        for path, _v, indirect in deps:
            hit = None if indirect else _prefix_match(path, GO)
            if hit:
                hits.append((path, hit))
        return hits
    found = manifest_parsers.parser_for_path(rel)
    if not found:
        return hits
    eco, parser = found
    try:
        _, deps = parser(text)
    except Exception:  # a malformed manifest only costs its signals
        return hits
    for dep, _v, _i in deps:
        if eco == "pypi":
            norm = re.sub(r"[-_.]+", "-", dep).lower()
            root = DECLARED_ALIASES["PyPI"].get(norm, norm.replace("-", "_"))
            hit = _python_match(root)
        elif eco == "npm":
            hit = _npm_match(dep)
        elif eco == "maven":
            hit = _prefix_match(dep.split(":", 1)[0], JAVA)
        elif eco == "cargo":
            hit = RUST.get(DECLARED_ALIASES["crates.io"].get(dep, dep.replace("-", "_")))
        else:
            hit = None
        if hit:
            hits.append((dep, hit))
    return hits


LOCKFILES = {
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Pipfile.lock",
    "uv.lock",
    "Cargo.lock",
    "gradle.lockfile",
    "go.sum",
}


def detect(repo: Path) -> dict:
    """The detection document: verdict, signals by kind, and tagged files."""
    repo = Path(repo).resolve()
    if not repo.is_dir():
        raise ValueError(f"not a directory: {repo}")
    signals: dict[tuple[str, str], dict] = {}
    files: dict[str, set[str]] = defaultdict(set)
    stats = {"source_files_read": 0, "manifests_read": 0, "skipped_large": 0}
    sources: dict[str, tuple[str, str]] = {}  # rel -> (lang, text), for the wrapper hop

    def note(kind: str, library: str, source: str, evidence: str) -> None:
        sig = signals.setdefault(
            (kind, library), {"kind": kind, "library": library, "via": set(), "evidence": []}
        )
        sig["via"].add(source)
        if len(sig["evidence"]) < 25 and evidence not in sig["evidence"]:
            sig["evidence"].append(evidence)

    for root, dirs, names in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for fname in sorted(names):
            path = Path(root) / fname
            rel = path.relative_to(repo).as_posix()
            lang = SOURCE_SUFFIXES.get(path.suffix)
            manifest = fname not in LOCKFILES and (
                fname == "go.mod" or manifest_parsers.parser_for_path(rel) is not None
            )
            prompt = _is_prompt_template(rel)
            if not (lang or manifest or prompt):
                continue
            if prompt:
                note("prompt-template", "prompt-files", "file", rel)
                files[rel].add("prompt-template")
            if not (lang or manifest):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    stats["skipped_large"] += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if lang:
                stats["source_files_read"] += 1
                sources[rel] = (lang, text)
                for lineno, (kind, library) in _imports(lang, text):
                    note(kind, library, "import", f"{rel}:{lineno}")
                    files[rel].add(kind)
            if manifest:
                stats["manifests_read"] += 1
                for dep, (kind, library) in _declared(repo, rel, text):
                    note(kind, library, "declared", f"{rel} ({dep})")

    # One deterministic hop: a file that imports an in-repo module that is
    # itself tagged (an internal wrapper around the SDK, the common shape)
    # uses the same library through it.
    via_wrapper: dict[str, set[str]] = defaultdict(set)
    tagged = {rel for rel, k in files.items() if k - {"prompt-template"}}
    known = set(sources)
    for rel, (lang, text) in sources.items():
        if rel in tagged:
            continue
        for target in _local_targets(lang, rel, text, known) & tagged:
            via_wrapper[rel].add(target)
    for rel, targets in via_wrapper.items():
        for target in targets:
            files[rel].update(files[target] - {"prompt-template"})

    out_signals = []
    for _key, sig in sorted(signals.items(), key=lambda kv: (KINDS.index(kv[0][0]), kv[0][1])):
        out_signals.append({**sig, "via": sorted(sig["via"])})
    kinds = sorted({s["kind"] for s in out_signals}, key=KINDS.index)
    return {
        "llm_application": bool(out_signals),
        "kinds": kinds,
        "signals": out_signals,
        "files": {rel: sorted(k, key=KINDS.index) for rel, k in sorted(files.items())},
        # files tagged only because they import a tagged in-repo module
        "files_via_wrapper": {rel: sorted(t) for rel, t in sorted(via_wrapper.items())},
        "stats": stats,
    }
