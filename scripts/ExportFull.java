//@category REA
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
