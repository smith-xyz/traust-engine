"""LLM, agent and MCP application detection: imports, declarations, prompts, negatives."""

from pathlib import Path

import pytest

from traust_engine.adapters import llm_app


def write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def libs(doc):
    return {(s["kind"], s["library"]) for s in doc["signals"]}


def test_a_plain_service_is_not_an_llm_application(tmp_path):
    write(tmp_path, "app.py", "import os\nfrom flask import Flask\n")
    write(tmp_path, "requirements.txt", "flask==3.0.0\n")
    doc = llm_app.detect(tmp_path)
    assert doc["llm_application"] is False
    assert doc["signals"] == [] and doc["files"] == {}


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        ("agent.py", "from openai import OpenAI\n", ("model-sdk", "openai")),
        ("a.py", "import anthropic, os\n", ("model-sdk", "anthropic")),
        ("g.py", "from google.genai import types\n", ("model-sdk", "google-genai")),
        (
            "lc.py",
            "from langchain_core.prompts import ChatPromptTemplate\n",
            ("agent-framework", "langchain"),
        ),
        ("srv.py", "from mcp.server.fastmcp import FastMCP\n", ("mcp-server", "mcp")),
        ("rag.py", "import chromadb\n", ("vector-store", "chromadb")),
        (
            "srv.ts",
            "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';\n",
            ("mcp-server", "mcp"),
        ),
        ("c.ts", 'const Anthropic = require("@anthropic-ai/sdk");\n', ("model-sdk", "anthropic")),
        (
            "l.ts",
            "import { ChatOpenAI } from '@langchain/openai';\n",
            ("agent-framework", "langchain"),
        ),
        ("v.ts", "import { generateText } from 'ai';\n", ("model-sdk", "vercel-ai-sdk")),
        (
            "m.go",
            'package m\n\nimport (\n\t"fmt"\n\tmcp "github.com/mark3labs/mcp-go/server"\n)\n',
            ("mcp-server", "mcp"),
        ),
        (
            "o.go",
            'package o\n\nimport "github.com/sashabaranov/go-openai"\n',
            ("model-sdk", "openai"),
        ),
        (
            "A.java",
            "import dev.langchain4j.model.chat.ChatModel;\n",
            ("agent-framework", "langchain4j"),
        ),
        ("main.rs", "use async_openai::Client;\n", ("model-sdk", "openai")),
    ],
)
def test_source_imports_are_detected_with_evidence(tmp_path, rel, text, expected):
    write(tmp_path, rel, text)
    doc = llm_app.detect(tmp_path)
    assert doc["llm_application"] is True
    assert expected in libs(doc)
    (sig,) = [s for s in doc["signals"] if (s["kind"], s["library"]) == expected]
    assert sig["via"] == ["import"]
    assert sig["evidence"][0].startswith(f"{rel}:")
    assert doc["files"][rel] == [expected[0]]


def test_lookalikes_are_not_matched(tmp_path):
    write(tmp_path, "x.py", "import openai_helpers_local\nfrom mcpx import y\n")
    write(tmp_path, "y.ts", "import x from './openai';\nimport z from 'aircraft';\n")
    write(tmp_path, "z.go", 'package z\n\nimport "github.com/openai/openai-gopher"\n')
    assert llm_app.detect(tmp_path)["signals"] == []


def test_direct_declarations_count_and_lockfiles_do_not(tmp_path):
    write(tmp_path, "requirements.txt", "langchain-core==0.3.0\nqdrant-client>=1.9\n")
    write(tmp_path, "web/package.json", '{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}')
    write(
        tmp_path,
        "web/package-lock.json",
        '{"packages": {"node_modules/openai": {"version": "4.0.0"}}}',
    )
    write(
        tmp_path,
        "go.mod",
        "module x\n\nrequire (\n\tgithub.com/tmc/langchaingo v0.1.0\n\tgithub.com/qdrant/go-client v1.0.0 // indirect\n)\n",
    )
    doc = llm_app.detect(tmp_path)
    assert libs(doc) == {
        ("agent-framework", "langchain"),
        ("vector-store", "qdrant"),
        ("mcp-server", "mcp"),
        ("agent-framework", "langchaingo"),
    }  # not openai (lockfile only), not the indirect qdrant go client
    assert all(s["via"] == ["declared"] for s in doc["signals"])
    assert doc["files"] == {}  # declarations tag no source file


def test_prompt_templates(tmp_path):
    write(tmp_path, "prompts/summarize.j2", "Summarize {{ text }}")
    write(tmp_path, "app/review.prompty", "---\nname: review\n---\n")
    write(tmp_path, "docs/notes.md", "not a prompt")
    doc = llm_app.detect(tmp_path)
    assert libs(doc) == {("prompt-template", "prompt-files")}
    assert set(doc["files"]) == {"prompts/summarize.j2", "app/review.prompty"}


def test_vendored_and_dependency_dirs_are_skipped(tmp_path):
    for d in ("node_modules/openai", "vendor/github.com/x", ".venv/lib", "site-packages/y"):
        write(tmp_path, f"{d}/index.py", "import openai\n")
    write(tmp_path, "node_modules/x/index.js", "require('openai')\n")
    assert llm_app.detect(tmp_path)["llm_application"] is False


def test_kinds_are_ordered_and_evidence_capped(tmp_path):
    for i in range(40):
        write(tmp_path, f"m{i}.py", "import openai\nimport chromadb\n")
    doc = llm_app.detect(tmp_path)
    assert doc["kinds"] == ["model-sdk", "vector-store"]
    assert all(len(s["evidence"]) <= 25 for s in doc["signals"])
    assert len(doc["files"]) == 40


def test_not_a_directory(tmp_path):
    with pytest.raises(ValueError):
        llm_app.detect(tmp_path / "missing")


def test_a_file_using_an_in_repo_wrapper_is_tagged(tmp_path):
    write(tmp_path, "app/llm.py", "from openai import OpenAI\n")
    write(tmp_path, "app/reports.py", "from app.llm import complete\n")
    write(tmp_path, "app/relative.py", "from .llm import complete\n")
    write(tmp_path, "app/plain.py", "import json\n")
    doc = llm_app.detect(tmp_path)
    assert doc["files"]["app/reports.py"] == ["model-sdk"]
    assert doc["files"]["app/relative.py"] == ["model-sdk"]
    assert "app/plain.py" not in doc["files"]
    assert doc["files_via_wrapper"] == {
        "app/relative.py": ["app/llm.py"],
        "app/reports.py": ["app/llm.py"],
    }


def test_the_wrapper_hop_covers_relative_js_imports(tmp_path):
    write(tmp_path, "src/lib/model.ts", "import OpenAI from 'openai';\n")
    write(tmp_path, "src/routes/chat.ts", "import { ask } from '../lib/model';\n")
    write(tmp_path, "src/routes/index.js", "const m = require('./chat.js');\n")
    doc = llm_app.detect(tmp_path)
    assert doc["files"]["src/routes/chat.ts"] == ["model-sdk"]
    # one hop only: index.js imports chat.ts, which is tagged only via the wrapper
    assert "src/routes/index.js" not in doc["files"]
