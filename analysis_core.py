import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
import xml.etree.ElementTree as ET

from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT / "reports"

LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".cs": "c_sharp",
    ".java": "java",
    ".go": "go",
    ".rs": "rust"
}

def find_command(name):
    return (
        shutil.which(name)
        or shutil.which(name + ".exe")
        or shutil.which(name + ".cmd")
    )

def load_config():
    path = ROOT / "config.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}

def ghidra_command():
    home = (
        load_config().get("ghidra_home")
        or os.environ.get("GHIDRA_HOME", "")
    )
    if home:
        p = Path(home)
        if p.is_dir():
            p = p / "support" / "analyzeHeadless.bat"
        if p.is_file():
            return str(p)
    return find_command("analyzeHeadless.bat")

def ilspy_command():
    candidate = Path.home() / ".dotnet" / "tools" / "ilspycmd.exe"
    return (
        find_command("ilspycmd")
        or (str(candidate) if candidate.is_file() else None)
    )

def engine_status():
    return {
        "Basic": True,
        "LIEF": importlib.util.find_spec("lief") is not None,
        "Tree-sitter": importlib.util.find_spec(
            "tree_sitter_language_pack"
        ) is not None,
        "Ghidra": bool(ghidra_command()),
        "ILSpy": bool(ilspy_command()),
        "REA": bool(find_command("npx"))
    }

def detect_type(path):
    p = Path(path).resolve(strict=True)

    if p.is_dir():
        if (p / "package.json").is_file():
            return "javascript_project"
        return "source_project"

    with p.open("rb") as f:
        header = f.read(4096)

    # Detect real PE files, including .exe.disabled
    if header.startswith(b"MZ") and len(header) >= 64:
        pe_offset = struct.unpack_from("<I", header, 0x3c)[0]

        if pe_offset < 1024 * 1024:
            with p.open("rb") as f:
                f.seek(pe_offset)
                pe = f.read(512)

            if pe.startswith(b"PE\x00\x00") and len(pe) >= 26:
                opt_size = struct.unpack_from("<H", pe, 20)[0]
                magic = struct.unpack_from("<H", pe, 24)[0]

                if magic in (0x10b, 0x20b):
                    directory_start = 96 if magic == 0x10b else 112
                    clr_offset = 24 + directory_start + 14 * 8

                    if clr_offset + 8 <= min(
                        len(pe), 24 + opt_size
                    ):
                        rva, size = struct.unpack_from(
                            "<II", pe, clr_offset
                        )
                        if rva != 0 and size != 0:
                            return "dotnet"
                return "pe"

    if header.startswith(b"\x7fELF"):
        return "elf"

    if header[:4] in (
        b"\xcf\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce"
    ):
        return "mach_o"

    if header.startswith(b"PK\x03\x04"):
        return "zip"

    if p.suffix.lower() == ".asar":
        return "asar"

    if p.suffix.lower() in LANGUAGES:
        return "source"

    if p.suffix.lower() in (
        ".json", ".xml", ".txt", ".md", ".yaml", ".yml"
    ):
        return "document"

    return "unknown"

def source_files(target, maximum=300):
    p = Path(target)

    if p.is_file():
        return [p] if p.suffix.lower() in LANGUAGES else []

    ignored = {
        ".git", "node_modules", ".venv", "venv",
        "__pycache__", "build", "dist", "target"
    }

    results = []

    for directory, folders, files in os.walk(
        p, followlinks=False
    ):
        folders[:] = [
            name for name in folders if name not in ignored
        ]

        for name in files:
            item = Path(directory) / name

            if item.is_symlink():
                continue

            if item.suffix.lower() not in LANGUAGES:
                continue

            try:
                if item.stat().st_size > 1024 * 1024:
                    continue
            except OSError:
                continue

            results.append(item)
            if len(results) >= maximum:
                return results

    return results

def basic_analysis(target):
    p = Path(target)

    if p.is_dir():
        return {
            "type": "project",
            "source_files": [
                str(x.relative_to(p))
                for x in source_files(p)[:150]
            ]
        }

    data = {
        "filename": p.name,
        "size_bytes": p.stat().st_size,
        "extension": p.suffix
    }

    if p.suffix.lower() == ".py":
        tree = ast.parse(
            p.read_text(encoding="utf-8", errors="replace")
        )
        data["symbols"] = [
            {
                "name": node.name,
                "line": node.lineno,
                "kind": type(node).__name__
            }
            for node in ast.walk(tree)
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
        ][:300]

    elif zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            data["archive_entries"] = len(z.infolist())
            data["sample_names"] = z.namelist()[:150]

    elif p.suffix.lower() == ".json":
        if p.stat().st_size <= 4 * 1024 * 1024:
            value = json.loads(p.read_text(encoding="utf-8-sig"))
            data["root_type"] = type(value).__name__
            if isinstance(value, dict):
                data["keys"] = list(value.keys())[:150]

    elif p.suffix.lower() == ".xml":
        if p.stat().st_size <= 2 * 1024 * 1024:
            raw = p.read_bytes()
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise RuntimeError("DTD/entity XML is not accepted")
            tree = ET.fromstring(raw)
            data["root_tag"] = tree.tag
            data["children"] = [x.tag for x in list(tree)[:100]]

    return data

def lief_analysis(target):
    import lief

    binary = lief.parse(str(target))

    if binary is None:
        raise RuntimeError("LIEF cannot parse this file")

    result = {
        "format": str(binary.format),
        "entrypoint": str(getattr(binary, "entrypoint", "")),
        "sections": [],
        "imports": []
    }

    for section in list(getattr(binary, "sections", []))[:150]:
        result["sections"].append({
            "name": section.name,
            "size": int(section.size)
        })

    for imp in list(getattr(binary, "imports", []))[:150]:
        result["imports"].append(str(imp.name))

    return result

def _treesitter_analysis_native(target):
    from tree_sitter import Parser
    from tree_sitter_language_pack import get_language

    files = source_files(target)
    parsers = {}
    symbols = []
    errors = []
    parsed = 0

    for file in files:
        lang = LANGUAGES[file.suffix.lower()]

        try:
            if lang not in parsers:
                parsers[lang] = Parser(get_language(lang))

            source_bytes = file.read_bytes()
            tree = parsers[lang].parse(source_bytes)
            parsed += 1
            stack = [tree.root_node]

            while stack and len(symbols) < 2000:
                node = stack.pop()

                if node.type in (
                    "function_definition",
                    "function_declaration",
                    "class_definition",
                    "class_declaration",
                    "method_definition",
                    "function_item",
                    "struct_item",
                    "class_specifier"
                ):
                    name_node = node.child_by_field_name("name")

                    symbol = (
                        source_bytes[name_node.start_byte:name_node.end_byte].decode(
                            "utf-8", errors="replace"
                        )[:120]
                        if name_node else "unknown"
                    )

                    symbols.append({
                        "file": str(file),
                        "line": node.start_point.row + 1,
                        "name": symbol,
                        "kind": node.type
                    })

                stack.extend(reversed(node.named_children))

        except Exception as exc:
            errors.append({
                "file": str(file),
                "reason": str(exc)[:200]
            })

    if parsed == 0:
        raise RuntimeError("No supported source files were parsed")

    return {
        "files_total": len(files),
        "files_parsed": parsed,
        "symbols_count": len(symbols),
        "symbols": symbols[:300],
        "errors": errors[:50]
    }


def treesitter_analysis(target):
    import tempfile

    with tempfile.TemporaryDirectory(prefix="rea_ts_") as temp:
        output = Path(temp) / "result.json"

        cmd = [
            sys.executable,
            "-X", "faulthandler",
            "-c", "import sys, json\nfrom pathlib import Path\nsys.path.insert(0, sys.argv[1])\nfrom analysis_core import _treesitter_analysis_native\ndata = _treesitter_analysis_native(sys.argv[2])\nPath(sys.argv[3]).write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')\n",
            str(ROOT),
            str(target),
            str(output)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=180,
                shell=False
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Tree-sitter worker timed out")

        if result.returncode != 0:
            error = (result.stderr or result.stdout)[-1200:]
            code = result.returncode & 0xFFFFFFFF
            raise RuntimeError(
                f"Tree-sitter subprocess failed: 0x{code:08X}\\n{error}"
            )

        if not output.is_file():
            raise RuntimeError("No analysis result generated")

        return json.loads(output.read_text(encoding="utf-8"))


def run_external(command, folder, prefix, timeout=1800, json_output=False):
    log = folder / (prefix + ".log")

    # cmd/bat files on Windows need special care with paths
    is_batch = str(command[0]).lower().endswith((".cmd", ".bat"))
    if is_batch:
        for item in command:
            if any(c in str(item) for c in '&|<>^%!"\n\r'):
                raise RuntimeError(
                    "Unsafe special character in batch command argument"
                )

    output_path = folder / (prefix + ".json")

    with log.open("wb") as stderr_file:
        if json_output:
            with output_path.open("wb") as stdout_file:
                result = subprocess.run(
                    command,
                    cwd=str(folder),
                    stdout=stdout_file,
                    stderr=stderr_file,
                    timeout=timeout,
                    shell=False
                )
        else:
            result = subprocess.run(
                command,
                cwd=str(folder),
                stdout=stderr_file,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                shell=False
            )

    if result.returncode != 0:
        details = log.read_text(
            encoding="utf-8", errors="replace"
        )[-1500:]
        raise RuntimeError(
            "Exit code: " + str(result.returncode)
            + "\n" + details
        )

    return output_path

def ghidra_analysis(target, folder):
    ghidra = ghidra_command()
    if not ghidra:
        raise RuntimeError("Ghidra is not configured")

    project_dir = folder / "ghidra_project"
    project_dir.mkdir(exist_ok=True)

    output = folder / "ghidra_symbols.json"

    command = [
        ghidra,
        str(project_dir),
        "AnalysisProject",
        "-import",
        str(target),
        "-scriptPath",
        str(ROOT / "scripts"),
        "-postScript",
        "ExportFindings.java",
        str(output),
        "-deleteProject"
    ]

    run_external(command, folder, "ghidra", timeout=1800)

    if not output.is_file():
        raise RuntimeError("Ghidra did not generate symbols JSON")

    data = json.loads(output.read_text(encoding="utf-8"))

    return {
        "functions_count": len(data.get("functions", [])),
        "functions_sample": data.get("functions", [])[:40],
        "raw_file": "ghidra_symbols.json"
    }

def ilspy_analysis(target, folder):
    tool = ilspy_command()
    if not tool:
        raise RuntimeError("ILSpy is not installed")

    output = folder / "ilspy_code"
    output.mkdir(exist_ok=True)

    run_external(
        [tool, "-p", "-o", str(output), str(target)],
        folder,
        "ilspy"
    )

    cs_files = list(output.rglob("*.cs"))

    if not cs_files:
        raise RuntimeError("ILSpy produced no C# source files")

    return {
        "decompiled_files": len(cs_files),
        "examples": [
            str(f.relative_to(output))
            for f in cs_files[:50]
        ],
        "output_directory": "ilspy_code"
    }

def rea_analysis(target, folder):
    npx = find_command("npx")
    if not npx:
        raise RuntimeError("Node.js/npm is missing")

    command = [
        npx,
        "-y",
        "rea-agents@latest",
        "analyze-javascript-application",
        str(target),
        "--json"
    ]

    output = run_external(
        command, folder, "rea",
        timeout=1800, json_output=True
    )

    if not output.exists() or output.stat().st_size == 0:
        raise RuntimeError("REA produced empty JSON")

    if output.stat().st_size > 32 * 1024 * 1024:
        return {
            "raw_file": "rea.json",
            "note": "Large report saved without full parsing"
        }

    content = json.loads(output.read_text(encoding="utf-8-sig"))

    if isinstance(content, dict):
        if content.get("success") is False or content.get("ok") is False:
            raise RuntimeError("REA JSON indicates failure")

    return {
        "raw_file": "rea.json",
        "root_keys": (
            list(content.keys())[:100]
            if isinstance(content, dict) else []
        )
    }

def route_engines(kind):
    routes = {
        "pe": ["Basic", "LIEF", "Ghidra"],
        "dotnet": ["Basic", "LIEF", "ILSpy"],
        "elf": ["Basic", "LIEF", "Ghidra"],
        "mach_o": ["Basic", "LIEF", "Ghidra"],
        "javascript_project": ["Basic", "Tree-sitter", "REA"],
        "asar": ["Basic", "REA"],
        "source_project": ["Basic", "Tree-sitter"],
        "source": ["Basic", "Tree-sitter"],
        "document": ["Basic"],
        "zip": ["Basic"],
        "unknown": ["Basic"]
    }
    return routes.get(kind, ["Basic"])

def execute_engine(name, target, folder):
    if name == "Basic":
        return basic_analysis(target)
    if name == "LIEF":
        return lief_analysis(target)
    if name == "Tree-sitter":
        return treesitter_analysis(target)
    if name == "Ghidra":
        return ghidra_analysis(target, folder)
    if name == "ILSpy":
        return ilspy_analysis(target, folder)
    if name == "REA":
        return rea_analysis(target, folder)
    raise RuntimeError("Unknown engine: " + name)

def analyze(target, notify=print):
    path = Path(target).resolve(strict=True)
    kind = detect_type(path)
    chosen = route_engines(kind)
    if path.is_file() and path.suffix.lower() == '.py':
        chosen = ['Basic']  # Python AST fallback
    available = engine_status()

    REPORTS.mkdir(exist_ok=True)

    safe_name = re.sub(r"[^\w.-]", "_", path.stem)[:50]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    folder = REPORTS / (safe_name + "_" + timestamp)
    folder.mkdir()

    record = {
        "target": str(path),
        "type": kind,
        "timestamp": datetime.now().isoformat(),
        "engines": [],
        "status": "pending"
    }

    if path.is_file():
        sha = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha.update(chunk)
        record["sha256"] = sha.hexdigest()

    notify("Target: " + str(path))
    notify("Detected: " + kind)
    notify("Engines: " + ", ".join(chosen))

    for engine_name in chosen:
        entry = {"engine": engine_name}

        if not available.get(engine_name, False):
            entry["status"] = "missing"
            entry["reason"] = "Engine is not installed/configured"
        else:
            try:
                result = execute_engine(engine_name, path, folder)

                filename = (
                    "result_"
                    + engine_name.lower().replace("-", "_")
                    + ".json"
                )
                (folder / filename).write_text(
                    json.dumps(result, ensure_ascii=False, indent=2),
                    encoding="utf-8"
                )

                entry["status"] = "completed"
                entry["result_file"] = filename
                entry["result"] = result

            except Exception as exc:
                entry["status"] = "failed"
                entry["reason"] = str(exc)[:1500]

        record["engines"].append(entry)
        notify(engine_name + ": " + entry["status"])

    done = sum(
        item["status"] == "completed"
        for item in record["engines"]
    )

    if kind == "unknown":
        record["status"] = "partial" if done else "failed"
    elif done == len(chosen):
        record["status"] = "completed"
    elif done > 0:
        record["status"] = "partial"
    else:
        record["status"] = "failed"

    (folder / "analysis.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )

    lines = [
        "# REA Universal Analyzer V2",
        "",
        "## Target",
        "",
        "- Path: `" + str(path) + "`",
        "- Format: `" + kind + "`",
        "- Status: **" + record["status"] + "**",
        "",
        "> The target executable was not launched.",
        "> Completed does not guarantee complete reverse engineering.",
        ""
    ]

    for item in record["engines"]:
        lines.extend([
            "## " + item["engine"],
            "",
            "- Status: **" + item["status"] + "**",
            ""
        ])

        if "reason" in item:
            lines.extend([
                "- Reason: " + item["reason"],
                ""
            ])

        if "result_file" in item:
            lines.extend([
                "- Full result: `" + item["result_file"] + "`",
                ""
            ])

        if "result" in item:
            output = json.dumps(
                item["result"],
                ensure_ascii=False,
                indent=2
            )
            limit = 4500
            if len(output) > limit:
                output = output[:limit] + "\n... [TRUNCATED]"

            lines.extend([
                "```json",
                output,
                "```",
                ""
            ])

    lines.extend([
        "## Instructions for AI",
        "",
        "Analyze the architecture and dependencies using the evidence.",
        "Distinguish observed facts from hypotheses.",
        "Identify missing analysis, unresolved calls, and failed engines.",
        "Use analysis.json and original engine outputs for verification.",
        ""
    ])

    summary = folder / "summary.md"
    summary.write_text(
        "\n".join(lines), encoding="utf-8"
    )


    try:
        from report_v21 import build_report
        build_report(folder)
        notify("V2.1 evidence report generated")
    except Exception as report_error:
        notify("V2.1 report error: " + str(report_error))
        with summary.open("a", encoding="utf-8") as f:
            f.write(
                "\n\n> V2.1 report generation failed. "
                "This is the V2 fallback report.\n"
            )

    notify("Status: " + record["status"])
    notify("Report: " + str(summary))

    return summary, record

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        print(json.dumps(
            engine_status(),
            ensure_ascii=False,
            indent=2
        ))
    elif len(sys.argv) >= 3 and sys.argv[1] == "--analyze":
        _, record = analyze(sys.argv[2])
        sys.exit(
            0 if record["status"] == "completed" else 2
        )
    else:
        print("Usage: analysis_core.py --check | --analyze PATH")
        sys.exit(1)