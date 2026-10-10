"""Export Ghidra functions.jsonl into readable pseudo-C."""
from pathlib import Path
from datetime import datetime
from tkinter import filedialog, messagebox
import json
import os
import queue
import threading

ROOT = Path(__file__).resolve().parent


def _safe_comment(text):
    return str(text).replace("*/", "* /").replace("\r", " ").replace("\n", " ")


def export_pseudocode(source, destination):
    source = Path(source).resolve(strict=True)
    destination = Path(destination).resolve()

    if not source.is_file() or source.name.lower() != "functions.jsonl":
        raise ValueError("请选择深度分析目录中的 functions.jsonl")

    if source == destination:
        raise ValueError("导出路径不能与原始 JSONL 相同")

    destination.parent.mkdir(parents=True, exist_ok=True)

    temp = destination.with_name(destination.name + ".rea_tmp")

    if temp.exists():
        raise FileExistsError(f"临时文件已存在：{temp}")

    total = decompiled = truncated = missing = 0

    try:
        with source.open("r", encoding="utf-8-sig") as reader, temp.open(
            "x", encoding="utf-8", newline="\n"
        ) as writer:

            writer.write("/* REA / Ghidra decompiled pseudocode\n")
            writer.write(" * This is NOT original source code and may not compile.\n")
            writer.write(f" * Input: {_safe_comment(source)}\n")
            writer.write(
                f" * Exported: {datetime.now().isoformat(timespec='seconds')}\n"
            )
            writer.write(" */\n\n")

            for line_no, line in enumerate(reader, 1):
                if not line.strip():
                    continue

                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"JSONL 第 {line_no} 行解析失败：{exc}"
                    ) from exc

                if not isinstance(item, dict):
                    raise ValueError(
                        f"JSONL 第 {line_no} 行不是函数对象"
                    )

                total += 1

                name = _safe_comment(item.get("name", "unknown"))
                address = _safe_comment(item.get("address", "unknown"))
                code = item.get("pseudocode")
                was_cut = item.get("code_truncated") is True

                truncated += int(was_cut)

                writer.write("/* ==========================================\n")
                writer.write(f" * Function #{total}: {name}\n")
                writer.write(f" * Address: {address}\n")

                if was_cut:
                    writer.write(
                        " * WARNING: pseudocode was truncated "
                        "during Ghidra export.\n"
                    )

                writer.write(" * ========================================== */\n")

                if isinstance(code, str) and code.strip():
                    decompiled += 1
                    writer.write(code)

                    if not code.endswith("\n"):
                        writer.write("\n")

                else:
                    missing += 1
                    writer.write(
                        "/* No pseudocode available for this function. */\n"
                    )

                writer.write("\n\n")

            if total == 0:
                raise ValueError(
                    "functions.jsonl 中没有函数记录"
                )

            writer.write(
                f"/* Export summary: {total} functions, "
                f"{decompiled} pseudocodes, "
                f"{missing} without code, "
                f"{truncated} truncated. */\n"
            )

        os.replace(temp, destination)

    finally:
        if temp.exists():
            temp.unlink()

    return {
        "total": total,
        "decompiled": decompiled,
        "missing": missing,
        "truncated": truncated,
        "output": str(destination),
    }


def _latest_report_dir():
    reports = ROOT / "reports"

    if not reports.is_dir():
        return ROOT

    candidates = [
        d for d in reports.iterdir()
        if d.is_dir() and (d / "functions.jsonl").is_file()
    ]

    if not candidates:
        return reports

    return max(
        candidates,
        key=lambda d: d.stat().st_mtime
    )


def open_export_dialog(parent):
    if getattr(parent, "_rea_export_running", False):
        messagebox.showinfo(
            "REA 导出",
            "导出仍在进行，请稍候。",
            parent=parent
        )
        return

    source_name = filedialog.askopenfilename(
        parent=parent,
        title="选择深度反编译报告中的 functions.jsonl",
        initialdir=str(_latest_report_dir()),
        filetypes=[
            ("JSON Lines", "*.jsonl"),
            ("所有文件", "*.*")
        ],
    )

    if not source_name:
        return

    source = Path(source_name)

    if source.name.lower() != "functions.jsonl":
        messagebox.showerror(
            "REA 导出",
            "请选 functions.jsonl 文件。",
            parent=parent
        )
        return

    output_name = filedialog.asksaveasfilename(
        parent=parent,
        title="保存为可阅读的 C 风格伪代码",
        initialdir=str(source.parent),
        initialfile=source.parent.name + "_pseudocode.c",
        defaultextension=".c",
        filetypes=[
            ("C 风格伪代码", "*.c"),
            ("文本文件", "*.txt")
        ],
    )

    if not output_name:
        return

    dest = Path(output_name)

    if dest.exists() and not messagebox.askyesno(
        "REA 导出",
        f"文件已经存在，确定覆盖吗？\n{dest}",
        parent=parent
    ):
        return

    result_queue = queue.Queue(maxsize=1)
    parent._rea_export_running = True

    def task():
        try:
            result = export_pseudocode(source, dest)
            result_queue.put((True, result))
        except Exception as exc:
            result_queue.put((False, str(exc)))

    def poll():
        try:
            success, result = result_queue.get_nowait()
        except queue.Empty:
            parent.after(120, poll)
            return

        parent._rea_export_running = False

        if success:
            messagebox.showinfo(
                "REA 导出完成",
                f"成功导出 {result['decompiled']} 份伪代码 / "
                f"{result['total']} 个函数。\n"
                f"缺失：{result['missing']}；"
                f"截断：{result['truncated']}。\n\n"
                f"保存位置：\n{result['output']}",
                parent=parent,
            )
        else:
            messagebox.showerror(
                "REA 导出失败",
                result,
                parent=parent
            )

    threading.Thread(
        target=task,
        daemon=True
    ).start()

    parent.after(120, poll)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Export REA JSONL to pseudo-C"
    )
    parser.add_argument("functions_jsonl")
    parser.add_argument("output_c", nargs="?")

    args = parser.parse_args()

    src = Path(args.functions_jsonl)

    if args.output_c:
        out = Path(args.output_c)
    else:
        out = src.with_name(
            src.parent.name + "_pseudocode.c"
        )

    print(export_pseudocode(src, out))
