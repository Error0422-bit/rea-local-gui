"""REA V2.2 full decompilation extension.
Python 3.11+; standard library only.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent

JAVA_SCRIPT = r'''//@category REA
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public class ExportFull extends GhidraScript {
    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 32) {
                        b.append(String.format("\\u%04x", (int)c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('\"').toString();
    }

    @Override
    protected void run() throws Exception {
        String[] a = getScriptArgs();
        if (a.length < 7) {
            throw new IllegalArgumentException(
                "Expected 7 arguments"
            );
        }
        if (currentProgram == null) {
            throw new IllegalStateException("No program loaded");
        }

        File dir = new File(a[0]);
        if (!dir.isDirectory()) {
            throw new IllegalArgumentException(
                "Report directory missing"
            );
        }

        int minutes = Integer.parseInt(a[1]);
        long maxBytes =
            Long.parseLong(a[2]) * 1024L * 1024L;
        int maxFunctions = Integer.parseInt(a[3]);
        int maxCalls = Integer.parseInt(a[4]);
        int maxCodeChars = Integer.parseInt(a[5]);
        int functionTimeout = Integer.parseInt(a[6]);

        long deadline =
            System.currentTimeMillis()
            + minutes * 60L * 1000L;

        int total = currentProgram
            .getFunctionManager().getFunctionCount();

        int written = 0;
        int success = 0;
        int failures = 0;
        int codeCut = 0;
        int callCount = 0;

        boolean callCut = false;
        long bytes = 0;
        String stopReason = "complete";

        DecompInterface dec = new DecompInterface();

        if (!dec.openProgram(currentProgram)) {
            throw new IllegalStateException(
                "Decompiler unavailable"
            );
        }

        FunctionIterator it = currentProgram
            .getFunctionManager().getFunctions(true);

        try (
            BufferedWriter fw = new BufferedWriter(
                new OutputStreamWriter(
                    new FileOutputStream(
                        new File(dir, "functions.jsonl")
                    ),
                    StandardCharsets.UTF_8
                )
            );
            BufferedWriter cw = new BufferedWriter(
                new OutputStreamWriter(
                    new FileOutputStream(
                        new File(dir, "calls.jsonl")
                    ),
                    StandardCharsets.UTF_8
                )
            )
        ) {
            while (it.hasNext()) {
                monitor.checkCancelled();

                if (System.currentTimeMillis() >= deadline) {
                    stopReason = "time_limit";
                    break;
                }
                if (
                    maxFunctions > 0
                    && written >= maxFunctions
                ) {
                    stopReason = "function_limit";
                    break;
                }
                if (bytes >= maxBytes) {
                    stopReason = "output_limit";
                    break;
                }

                Function f = it.next();
                String address =
                    f.getEntryPoint().toString();

                String code = null;
                boolean truncated = false;

                try {
                    DecompileResults result =
                        dec.decompileFunction(
                            f, functionTimeout, monitor
                        );

                    if (
                        result != null
                        && result.decompileCompleted()
                        && result.getDecompiledFunction() != null
                    ) {
                        code = result
                            .getDecompiledFunction().getC();
                    }
                } catch (Exception ex) {
                    printerr(
                        "Decompile warning "
                        + address + ": "
                        + ex.getMessage()
                    );
                }

                if (code != null) {
                    success++;

                    if (code.length() > maxCodeChars) {
                        code = code.substring(
                            0, maxCodeChars
                        );
                        truncated = true;
                        codeCut++;
                    }
                } else {
                    failures++;
                }

                String row =
                    "{\"name\":" + q(f.getName())
                    + ",\"address\":" + q(address)
                    + ",\"decompiled\":"
                    + (code != null)
                    + ",\"code_truncated\":"
                    + truncated
                    + ",\"pseudocode\":" + q(code)
                    + "}\n";

                long rowBytes = row.getBytes(
                    StandardCharsets.UTF_8
                ).length;

                if (bytes + rowBytes > maxBytes) {
                    stopReason = "output_limit";
                    break;
                }

                fw.write(row);
                bytes += rowBytes;
                written++;

                if (
                    maxCalls > 0
                    && callCount >= maxCalls
                ) {
                    callCut = true;
                } else {
                    try {
                        Set<Function> targets =
                            f.getCalledFunctions(monitor);

                        for (Function dest : targets) {
                            if (
                                maxCalls > 0
                                && callCount >= maxCalls
                            ) {
                                callCut = true;
                                break;
                            }

                            String call =
                                "{\"source\":"
                                + q(address)
                                + ",\"target\":"
                                + q(
                                    dest.getEntryPoint()
                                        .toString()
                                )
                                + ",\"target_name\":"
                                + q(dest.getName())
                                + "}\n";

                            long callBytes =
                                call.getBytes(
                                    StandardCharsets.UTF_8
                                ).length;

                            if (
                                bytes + callBytes > maxBytes
                            ) {
                                stopReason = "output_limit";
                                break;
                            }

                            cw.write(call);
                            bytes += callBytes;
                            callCount++;
                        }
                    } catch (Exception ex) {
                        printerr(
                            "Call graph warning "
                            + address + ": "
                            + ex.getMessage()
                        );
                    }
                }

                if (written % 10 == 0) {
                    fw.flush();
                    cw.flush();
                }

                if (stopReason.equals("output_limit")) {
                    break;
                }
            }
        } finally {
            dec.dispose();
        }

        String status =
            "{\"total_functions\":" + total
            + ",\"functions_written\":" + written
            + ",\"pseudocode_written\":" + success
            + ",\"decompile_failures\":" + failures
            + ",\"pseudocode_truncated\":" + codeCut
            + ",\"calls_written\":" + callCount
            + ",\"calls_truncated\":" + callCut
            + ",\"stop_reason\":"
            + q(stopReason) + "}";

        try (
            BufferedWriter w = new BufferedWriter(
                new OutputStreamWriter(
                    new FileOutputStream(
                        new File(dir, "full_stats.json")
                    ),
                    StandardCharsets.UTF_8
                )
            )
        ) {
            w.write(status);
        }

        println(
            "REA full export: " + written
            + "/" + total + " functions, "
            + success + " pseudocodes"
        );
    }
}
'''


def settings():
    default = {
        "timeout_minutes": 60,
        "analysis_grace_minutes": 25,
        "max_output_mb": 256,
        "max_functions": 0,
        "max_calls": 100000,
        "max_code_chars": 60000,
        "function_timeout_seconds": 15,
    }

    path = ROOT / "config.json"

    if path.is_file():
        obj = json.loads(
            path.read_text(encoding="utf-8-sig")
        )
        if (
            isinstance(obj, dict)
            and isinstance(obj.get("full_mode"), dict)
        ):
            default.update(obj["full_mode"])

    limits = {
        "timeout_minutes": (1, 240),
        "analysis_grace_minutes": (1, 120),
        "max_output_mb": (1, 4096),
        "max_functions": (0, 500000),
        "max_calls": (0, 2000000),
        "max_code_chars": (100, 500000),
        "function_timeout_seconds": (1, 120),
    }

    for name, (low, high) in limits.items():
        value = default[name]
        if (
            type(value) is not int
            or not low <= value <= high
        ):
            raise ValueError(
                f"Invalid full_mode.{name}: {value!r}"
            )

    return default


def count_jsonl(path):
    count = 0
    sample = []
    invalid = 0

    if not path.exists():
        return count, sample, invalid

    with path.open(
        "r", encoding="utf-8", errors="replace"
    ) as f:
        for line in f:
            if not line.strip():
                continue

            try:
                item = json.loads(line)
                count += 1
                if len(sample) < 8:
                    sample.append(item)
            except ValueError:
                invalid += 1

    return count, sample, invalid


def analyze_full(target, notify=print):
    from analysis_core import (
        analyze,
        detect_type,
        ghidra_command,
    )

    p = Path(target).resolve(strict=True)
    kind = detect_type(p)

    if kind == "dotnet":
        notify(
            ".NET assembly: using ILSpy workflow"
        )
        return analyze(str(p), notify)

    if not p.is_file() or kind != "pe":
        raise ValueError(
            "Full mode supports single native Windows "
            "EXE/DLL files. Use Quick for other targets."
        )

    exe = ghidra_command()

    if not exe:
        raise RuntimeError(
            "Ghidra is not configured"
        )

    if not (
        ROOT / "scripts" / "ExportFull.java"
    ).is_file():
        raise RuntimeError(
            "ExportFull.java missing; run --install"
        )

    opt = settings()

    safe = re.sub(
        r"[^\w.-]", "_", p.stem
    )[:40]

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    out = (
        ROOT / "reports" / (
            safe + "_full_" + stamp
        )
    )
    out.mkdir(parents=True)

    log = out / "ghidra_full.log"
    project = out / "ghidra_project"
    project.mkdir()

    cmd = [
        str(exe),
        str(project),
        "REAFull",
        "-import",
        str(p),
        "-scriptPath",
        str(ROOT / "scripts"),
        "-postScript",
        "ExportFull.java",
        str(out),
        str(opt["timeout_minutes"]),
        str(opt["max_output_mb"]),
        str(opt["max_functions"]),
        str(opt["max_calls"]),
        str(opt["max_code_chars"]),
        str(opt["function_timeout_seconds"]),
        "-deleteProject",
    ]

    # Ghidra uses a Windows batch launcher.
    if any(
        any(c in arg for c in '&|<>^%!"\r\n')
        for arg in cmd
    ):
        raise ValueError(
            "Unsupported Windows batch special "
            "character in path"
        )

    notify(
        f"Full Ghidra analysis started: {p}"
    )

    exit_code = None
    timed_out = False

    with log.open("wb") as f:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                shell=False,
            )

            try:
                exit_code = proc.wait(
                    timeout=(
                        opt["timeout_minutes"]
                        + opt["analysis_grace_minutes"]
                    ) * 60
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                notify(
                    "Time limit reached; "
                    "preserving partial output"
                )

                if os.name == "nt":
                    subprocess.run(
                        [
                            "taskkill",
                            "/PID", str(proc.pid),
                            "/T", "/F"
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=30,
                    )

                if proc.poll() is None:
                    proc.kill()
                proc.wait()

        except OSError as ex:
            notify(
                f"Ghidra launch failed: {ex}"
            )

    stats_file = out / "full_stats.json"
    stats = None

    if stats_file.exists():
        try:
            stats = json.loads(
                stats_file.read_text(
                    encoding="utf-8"
                )
            )
        except ValueError:
            pass

    funcs, samples, fn_bad = count_jsonl(
        out / "functions.jsonl"
    )
    calls, _, call_bad = count_jsonl(
        out / "calls.jsonl"
    )

    complete = (
        exit_code == 0
        and stats is not None
        and stats.get("stop_reason") == "complete"
        and stats.get("functions_written") == funcs
        and stats.get("calls_written") == calls
        and not stats.get("calls_truncated")
        and stats.get("decompile_failures") == 0
        and stats.get("pseudocode_truncated") == 0
        and fn_bad == 0
        and call_bad == 0
    )

    state = (
        "completed"
        if complete
        else "partial" if funcs > 0 else "failed"
    )

    info = {
        "target": str(p),
        "type": kind,
        "mode": "full",
        "status": state,
        "ghidra_exit_code": exit_code,
        "timed_out": timed_out,
        "functions_records": funcs,
        "calls_records": calls,
        "invalid_function_records": fn_bad,
        "invalid_call_records": call_bad,
        "stats": stats,
        "limitations": [
            "Pseudocode is approximate, "
            "not original source code.",
            "Indirect calls and dynamic "
            "behavior may be missing.",
            "Partial may indicate output limits "
            "or failed decompilation."
        ],
    }

    (out / "analysis.json").write_text(
        json.dumps(
            info, indent=2, ensure_ascii=False
        ),
        encoding="utf-8"
    )

    lines = [
        "# REA Full Decompilation Report",
        "",
        f"- Target: `{p}`",
        "- Mode: Full (Ghidra)",
        f"- Status: **{state}**",
        f"- Functions exported: **{funcs}**",
        f"- Call edges exported: **{calls}**",
        "",
        "> Static pseudocode, not original source.",
        "",
        "## Ghidra statistics",
        "",
    ]

    if stats:
        lines.extend([
            "```json",
            json.dumps(stats, indent=2),
            "```",
        ])
    else:
        lines.append(
            "No final statistics. "
            "Inspect ghidra_full.log."
        )

    lines.extend([
        "",
        "## Function samples",
        "",
        "| Address | Name | Decompiled |",
        "|---|---|---|",
    ])

    for item in samples:
        name = str(
            item.get("name", "")
        ).replace("|", "/")[:90]

        lines.append(
            f"| `{item.get('address','')}` "
            f"| {name} "
            f"| {bool(item.get('pseudocode'))} |"
        )

    lines.extend([
        "",
        "## Evidence files",
        "",
        "- `functions.jsonl` — per-function pseudocode",
        "- `calls.jsonl` — static call relations",
        "- `full_stats.json` — analysis completion",
        "- `ghidra_full.log` — execution log",
        "",
        "## Instructions for AI",
        "",
        "Read relevant JSONL records selectively. "
        "Distinguish recovered evidence from inference. "
        "Report truncated code, failed functions, "
        "and unresolved calls."
    ])

    report = out / "summary.md"
    report.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8"
    )

    notify(
        f"Full mode: {state}; "
        f"functions={funcs}; calls={calls}"
    )
    notify(f"Report: {report}")

    return report, info


def analyze_with_mode(mode, target, notify=print):
    if mode == "quick":
        from analysis_core import analyze
        return analyze(target, notify)

    if mode == "full":
        return analyze_full(target, notify)

    raise ValueError(
        "Unknown analysis mode"
    )


def install():
    gui = ROOT / "rea_gui.py"
    core = ROOT / "analysis_core.py"
    java = ROOT / "scripts" / "ExportFull.java"

    if (
        not gui.is_file()
        or not core.is_file()
        or not java.parent.is_dir()
    ):
        raise RuntimeError(
            "Existing REA GUI V2.2 "
            "installation not found"
        )

    text = gui.read_text(
        encoding="utf-8-sig"
    )

    if (
        "from full_decompile "
        "import analyze_with_mode"
    ) in text:
        print("GUI already patched.")
        return

    patches = [
        (
            "from analysis_core import "
            "analyze, engine_status, REPORTS",
            "from analysis_core import "
            "analyze, engine_status, REPORTS\n"
            "from full_decompile import "
            "analyze_with_mode",
        ),
        (
            "        self.start_button = ttk.Button(",
            "        self.mode = "
            "tk.StringVar(value='quick')\n"
            "        ttk.Radiobutton("
            "controls, text='快速分析', "
            "variable=self.mode, value='quick'"
            ").pack(side='left', padx=5)\n"
            "        ttk.Radiobutton("
            "controls, text='尽可能完整反编译', "
            "variable=self.mode, value='full'"
            ").pack(side='left', padx=5)\n"
            "        self.start_button = ttk.Button(",
        ),
        (
            "        self.running = True\n"
            "        self.latest = None",
            "        self.run_mode = self.mode.get()\n"
            "        self.running = True\n"
            "        self.latest = None",
        ),
        (
            "report, record = analyze(",
            "report, record = "
            "analyze_with_mode(self.run_mode, ",
        ),
    ]

    for before, after in patches:
        if text.count(before) != 1:
            raise RuntimeError(
                "GUI layout unexpected. "
                "No changes made: "
                + before[:45]
            )
        text = text.replace(
            before, after, 1
        )

    compile(text, str(gui), "exec")

    backup = ROOT / (
        "backup_before_full_"
        + datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )
    )
    backup.mkdir()

    shutil.copy2(
        gui, backup / gui.name
    )

    if java.exists():
        shutil.copy2(
            java, backup / java.name
        )

    temp_gui = gui.with_suffix(".installing")
    temp_java = java.with_suffix(".installing")

    temp_gui.write_text(
        text, encoding="utf-8"
    )
    temp_java.write_text(
        JAVA_SCRIPT, encoding="utf-8"
    )

    temp_java.replace(java)
    temp_gui.replace(gui)

    print("FULL MODE INSTALLED")
    print("Backup:", backup)
    print("Java exporter:", java)
    print("GUI:", gui)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--install",
        action="store_true"
    )

    parser.add_argument(
        "--mode",
        choices=("quick", "full"),
        default="full"
    )

    parser.add_argument(
        "target", nargs="?"
    )

    args = parser.parse_args()

    if args.install:
        install()
        return

    if not args.target:
        parser.error("Target file is required")

    report, record = analyze_with_mode(
        args.mode, args.target
    )

    print("Status:", record["status"])
    print("Report:", report)

    if record["status"] == "failed":
        sys.exit(2)


if __name__ == "__main__":
    main()