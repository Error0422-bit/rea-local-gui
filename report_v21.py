import argparse
import json
import shutil
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX_JSON_SIZE = 64 * 1024 * 1024
MAX_NODES = 60
MAX_EDGES = 80


def read_json(path):
    if not path.exists():
        return None

    if path.stat().st_size > MAX_JSON_SIZE:
        raise ValueError(
            f"JSON exceeds 64 MiB: {path}"
        )

    return json.loads(
        path.read_text(encoding="utf-8-sig")
    )


def compact(value, limit=140):
    if isinstance(value, (dict, list)):
        value = json.dumps(
            value, ensure_ascii=False, default=str
        )
    text = str(value if value is not None else "")
    text = " ".join(text.split())
    return text[:limit]


def cell(value, limit=140):
    return compact(value, limit).replace("|", "/")


def node_label(node, hints):
    kind = compact(node.get("kind", "unknown"), 35)
    node_id = node.get("node_id", "")
    name = None

    for key in ("path", "name", "label", "module_key"):
        if node.get(key):
            name = node[key]
            break

    if not name:
        for observation in node.get("observations", []):
            if not isinstance(observation, dict):
                continue

            props = observation.get("properties") or {}
            if not isinstance(props, dict):
                continue

            for key in (
                "path", "logical_module_key",
                "module_key", "name",
                "specifier", "package_name"
            ):
                if props.get(key):
                    name = props[key]
                    break

            if name:
                break

    if not name:
        name = hints.get(node_id)

    if not name:
        name = node_id[:10] or "unknown"

    return kind + ": " + compact(name, 75)


def edge_location(edge):
    evidence = edge.get("evidence") or {}
    loc = evidence.get("location") or {}
    value = loc.get("value") or {}

    if not isinstance(value, dict):
        return "未提供"

    source = value.get("source") or value.get("path")

    start = value.get("start") or {}
    line = start.get("line") if isinstance(start, dict) else None

    if source and line is not None:
        return f"{source}:{line}"

    if source:
        return str(source)

    return "未提供"


def edge_evidence(edge):
    evidence = edge.get("evidence") or {}

    parts = []
    for key in ("authority", "state", "confidence"):
        if evidence.get(key):
            parts.append(str(evidence[key]))

    coverage = evidence.get("coverage") or {}
    if isinstance(coverage, dict):
        if coverage.get("truncated"):
            parts.append("TRUNCATED")

    return ", ".join(parts) or "未提供"


def mermaid_label(value):
    return (
        compact(value, 95)
        .replace("\\", "/")
        .replace('"', "'")
        .replace("<", "(")
        .replace(">", ")")
        .replace("|", "/")
    )


def add_graph(lines, rea):
    normalized = rea.get("normalized_result") or {}
    graph = normalized.get("graph") or {}

    if not isinstance(graph, dict):
        lines.append("REA graph 不存在或格式异常。")
        return

    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    nodes = [n for n in nodes if isinstance(n, dict)]
    edges = [e for e in edges if isinstance(e, dict)]

    lines.extend([
        "## 2. REA 应用结构图",
        "",
        f"- Graph schema: `{cell(graph.get('schema'))}`",
        f"- 节点总数：**{len(nodes)}**",
        f"- 关系总数：**{len(edges)}**",
        f"- Graph ID：`{cell(graph.get('graph_id'))}`",
        "",
        "> 这些是静态分析关系，不等于运行时调用已经发生。",
        ""
    ])

    kinds = Counter(
        str(n.get("kind", "unknown")) for n in nodes
    )
    relations = Counter(
        str(e.get("relation", "unknown")) for e in edges
    )

    lines.extend(["### 节点类型", ""])
    for kind, count in kinds.most_common():
        lines.append(f"- `{cell(kind)}`：{count}")

    lines.extend(["", "### 关系类型", ""])
    for relation, count in relations.most_common():
        lines.append(f"- `{cell(relation)}`：{count}")

    lines.append("")

    hints = {}
    for e in edges:
        props = e.get("properties") or {}

        if not isinstance(props, dict):
            continue

        if e.get("relation") == "contains":
            hint = (
                props.get("path")
                or props.get("logical_module_key")
            )
            if hint:
                hints.setdefault(
                    e.get("target_node_id"), str(hint)
                )

    labels = {
        n.get("node_id"): node_label(n, hints)
        for n in nodes
    }

    lines.extend([
        "### 结构节点",
        "",
        "| 类型与节点 |",
        "|---|"
    ])

    for n in nodes[:MAX_NODES]:
        lines.append(
            f"| {cell(labels.get(n.get('node_id')), 115)} |"
        )

    if len(nodes) > MAX_NODES:
        lines.append(
            f"\n_其余 {len(nodes)-MAX_NODES} 个节点未列出。_"
        )

    lines.extend([
        "",
        "### Mermaid 静态结构图",
        "",
        "```mermaid",
        "flowchart LR"
    ])

    selected = nodes[:MAX_NODES]
    ids = {
        n.get("node_id"): f"N{i}"
        for i, n in enumerate(selected)
    }

    for node_id, mermaid_id in ids.items():
        label = mermaid_label(
            labels.get(node_id, "unknown")
        )
        lines.append(
            f'    {mermaid_id}["{label}"]'
        )

    drawn = 0

    for edge in edges[:MAX_EDGES]:
        a = ids.get(edge.get("source_node_id"))
        b = ids.get(edge.get("target_node_id"))

        if a is None or b is None:
            continue

        relation = mermaid_label(
            edge.get("relation", "relationship")
        )

        lines.append(
            f'    {a} -->|"{relation}"| {b}'
        )
        drawn += 1

    lines.extend(["```", ""])

    if drawn < len(edges):
        lines.append(
            f"_图中展示 {drawn}/{len(edges)} 条关系；"
            "其余关系可能受到节点或数量限制。_"
        )
        lines.append("")

    lines.extend([
        "### 关系与证据",
        "",
        "| 来源节点 | 关系 | 目标节点 | 位置 | 证据状态 |",
        "|---|---|---|---|---|"
    ])

    for edge in edges[:MAX_EDGES]:
        source = labels.get(
            edge.get("source_node_id"),
            "未知来源节点"
        )
        target = labels.get(
            edge.get("target_node_id"),
            "未知目标节点"
        )

        lines.append(
            f"| {cell(source, 70)} "
            f"| {cell(edge.get('relation'), 45)} "
            f"| {cell(target, 70)} "
            f"| {cell(edge_location(edge), 90)} "
            f"| {cell(edge_evidence(edge), 95)} |"
        )

    if len(edges) > MAX_EDGES:
        lines.append(
            f"\n_还有 {len(edges)-MAX_EDGES} 条关系"
            "保存在原始 JSON 中。_"
        )

    lines.extend(["", "### 覆盖情况", ""])

    coverage = graph.get("coverage")
    if coverage is not None:
        lines.extend([
            "```json",
            json.dumps(
                coverage, ensure_ascii=False, indent=2
            )[:2000],
            "```",
            ""
        ])
    else:
        lines.append("没有提供覆盖情况。")

    all_limits = []
    for source in (
        rea.get("limitations"),
        graph.get("limitations")
    ):
        if isinstance(source, list):
            all_limits.extend(source)

    lines.extend(["", "### REA 分析限制", ""])

    if all_limits:
        for limitation in dict.fromkeys(
            compact(x, 400) for x in all_limits
        ):
            lines.append("- " + limitation)
    else:
        lines.append("- 未提供具体限制。")

    lines.append("")


def add_ghidra(lines, folder):
    path = folder / "ghidra_symbols.json"
    data = read_json(path)

    if not isinstance(data, dict):
        return

    functions = data.get("functions") or []

    count = sum(
        isinstance(f, dict) and bool(f.get("pseudocode"))
        for f in functions
    )

    lines.extend([
        "## 3. Ghidra 反编译结果",
        "",
        f"- 导出函数数量：**{len(functions)}**",
        f"- 包含伪代码的函数：**{count}**",
        "- 完整数据：`ghidra_symbols.json`",
        "",
        "| 函数名 | 地址 | 是否有伪代码 |",
        "|---|---|---|"
    ])

    for f in functions[:30]:
        if not isinstance(f, dict):
            continue
        lines.append(
            f"| {cell(f.get('name'))} "
            f"| `{cell(f.get('address'))}` "
            f"| {'是' if f.get('pseudocode') else '否'} |"
        )

    samples = [
        f for f in functions
        if isinstance(f, dict) and f.get("pseudocode")
    ][:2]

    for f in samples:
        code = str(f["pseudocode"])[:900]
        lines.extend([
            "",
            f"### 伪代码示例：`{cell(f.get('name'))}`",
            "",
            "~~~c",
            code,
            "~~~"
        ])

    lines.extend([
        "",
        "> 伪代码是反编译结果，不等于原始源码。",
        ""
    ])



def add_ghidra_calls(lines, folder):
    data = read_json(folder / "ghidra_symbols.json")
    if not isinstance(data, dict):
        return

    calls = data.get("calls") or []
    meta = data.get("metadata") or {}

    lines.extend([
        "## Ghidra 静态函数调用关系",
        "",
        f"- 已导出关系：**{len(calls)}**",
        f"- 导出函数：{meta.get('functions_exported', '?')}",
        f"- 伪代码数量：{meta.get('pseudocode_exported', '?')}",
        f"- 函数列表截断：{meta.get('functions_truncated', '?')}",
        "",
        "> 仅包含 Ghidra 静态识别的部分调用关系。",
        "> 间接调用、动态加载等可能无法恢复。",
        "",
        "| 调用者 | 被调用函数 |",
        "|---|---|"
    ])

    for call in calls[:100]:
        lines.append(
            f"| {cell(call.get('source_name'), 75)} "
            f"| {cell(call.get('target_name'), 75)} |"
        )

    if len(calls) > 100:
        lines.append(
            f"\\n_其余 {len(calls)-100} 条关系"
            "请查看 ghidra_symbols.json。_"
        )

    lines.extend([
        "",
        "### 局部调用关系图",
        "",
        "```mermaid",
        "flowchart LR"
    ])

    ids = {}
    names = {}

    for call in calls[:35]:
        for prefix in ("source", "target"):
            addr = call.get(prefix + "_address")
            if addr not in ids:
                ids[addr] = "F" + str(len(ids))
                names[addr] = call.get(prefix + "_name", addr)

    for addr, node_id in ids.items():
        label = mermaid_label(names[addr])
        lines.append(f'    {node_id}["{label}"]')

    for call in calls[:35]:
        a = ids[call.get("source_address")]
        b = ids[call.get("target_address")]
        lines.append(f"    {a} --> {b}")

    lines.extend(["```", ""])


def add_other_results(lines, folder):
    for name, title in (
        ("result_tree_sitter.json", "Tree-sitter"),
        ("result_basic.json", "Basic"),
        ("result_ilspy.json", "ILSpy"),
        ("result_lief.json", "LIEF")
    ):
        path = folder / name
        data = read_json(path)

        if data is None:
            continue

        lines.extend([
            f"## {title} 分析结果",
            "",
            f"- 原始结果：`{name}`",
            "",
            "```json",
            json.dumps(
                data, ensure_ascii=False, indent=2
            )[:3500],
            "```",
            ""
        ])


def build_report(folder):
    folder = Path(folder).resolve()
    analysis = read_json(folder / "analysis.json")

    if not isinstance(analysis, dict):
        raise ValueError("analysis.json missing or invalid")

    rea = read_json(folder / "rea.json")
    summary = folder / "summary.md"
    original = folder / "summary_v2_original.md"

    lines = [
        "# REA Universal Analyzer V2.1",
        "",
        "## 1. 分析任务",
        "",
        f"- 目标：`{analysis.get('target', 'unknown')}`",
        f"- 格式：`{analysis.get('type', 'unknown')}`",
        f"- 状态：**{analysis.get('status', 'unknown')}**",
        f"- 分析时间：`{analysis.get('timestamp', '')}`",
        "",
        "### 引擎执行情况",
        "",
        "| 引擎 | 状态 | 问题 |",
        "|---|---|---|"
    ]

    for entry in analysis.get("engines", []):
        if not isinstance(entry, dict):
            continue
        lines.append(
            f"| {cell(entry.get('engine'))} "
            f"| {cell(entry.get('status'))} "
            f"| {cell(entry.get('reason', ''), 180)} |"
        )

    lines.append("")

    if isinstance(rea, dict):
        lines.extend([
            "### REA 证据元信息",
            "",
            f"- Evidence ID：`{cell(rea.get('evidence_id'))}`",
            f"- Authority：`{cell(rea.get('authority'))}`",
            f"- Confidence：`{cell(rea.get('confidence'))}`",
            f"- Predicate：`{cell(rea.get('predicate_type'))}`",
            "",
        ])
        add_graph(lines, rea)

    add_ghidra(lines, folder)
    add_ghidra_calls(lines, folder)
    add_other_results(lines, folder)

    lines.extend([
        "## AI 后续分析要求",
        "",
        "1. 基于文件、节点、边及证据解释架构。",
        "2. 严格区分静态依赖与运行时调用。",
        "3. 区分实际证据、推断和未知信息。",
        "4. 标记 failed、missing 和 partial 引擎。",
        "5. 如果摘要不充分，定向读取原始 JSON。",
        "6. 不要将不存在的函数关系或模块视为已证实。",
        "",
        "## 原始证据文件",
        "",
        "- `analysis.json`：引擎执行状态",
        "- `rea.json`：REA 完整应用图与证据",
        "- `ghidra_symbols.json`：反编译函数和伪代码（如有）",
        "- `result_*.json`：其他引擎结果（如有）",
        ""
    ])

    if summary.exists() and not original.exists():
        shutil.copy2(summary, original)

    tmp = folder / "summary_v21.tmp"
    tmp.write_text(
        "\n".join(lines), encoding="utf-8"
    )
    tmp.replace(summary)

    return summary


def install_hook():
    core = ROOT / "analysis_core.py"

    if not core.exists():
        raise FileNotFoundError(core)

    source = core.read_text(encoding="utf-8")

    if "from report_v21 import build_report" in source:
        print("V2.1 hook already installed.")
        return

    anchor = '    notify("Status: " + record["status"])'

    if source.count(anchor) != 1:
        raise RuntimeError(
            "Could not find V2 report hook position. "
            "No changes made."
        )

    hook = '''
    try:
        from report_v21 import build_report
        build_report(folder)
        notify("V2.1 evidence report generated")
    except Exception as report_error:
        notify("V2.1 report error: " + str(report_error))
        with summary.open("a", encoding="utf-8") as f:
            f.write(
                "\\n\\n> V2.1 report generation failed. "
                "This is the V2 fallback report.\\n"
            )

'''

    updated = source.replace(anchor, hook + anchor, 1)

    # Check Python syntax before modifying the application.
    compile(updated, str(core), "exec")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = ROOT / (
        "analysis_core.py.before_v21_" + stamp + ".bak"
    )

    shutil.copy2(core, backup)

    tmp = ROOT / "analysis_core.v21.tmp"
    tmp.write_text(updated, encoding="utf-8")
    tmp.replace(core)

    print("V2.1 installed successfully.")
    print("Backup:", backup)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--report", help="Existing analysis report directory"
    )
    parser.add_argument(
        "--install", action="store_true"
    )
    args = parser.parse_args()

    if not args.report and not args.install:
        parser.error("Specify --report or --install")

    if args.report:
        result = build_report(args.report)
        print("REPORT GENERATED:", result)

    if args.install:
        install_hook()


if __name__ == "__main__":
    main()