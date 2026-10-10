
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

//@category REA

public class ExportFindings extends GhidraScript {

    private static final int MAX_FUNCTIONS = 2000;
    private static final int MAX_PSEUDOCODE = 60;
    private static final int MAX_CALLS = 3000;
    private static final int MAX_CALLS_PER_FUNCTION = 60;

    private String quote(String s) {
        if (s == null) return "\"\"";

        StringBuilder b = new StringBuilder("\"");

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
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

        return b.append('"').toString();
    }

    @Override
    protected void run() throws Exception {

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Output path required"
            );
        }

        if (currentProgram == null) {
            throw new IllegalStateException(
                "No program loaded"
            );
        }

        DecompInterface decompiler =
            new DecompInterface();

        if (!decompiler.openProgram(currentProgram)) {
            throw new IllegalStateException(
                "Decompiler unavailable"
            );
        }

        ArrayList<String> calls = new ArrayList<>();
        HashSet<String> seen = new HashSet<>();

        int count = 0;
        int pseudocodeCount = 0;
        FunctionIterator it = currentProgram
            .getFunctionManager().getFunctions(true);

        try (
            BufferedWriter out = new BufferedWriter(
                new OutputStreamWriter(
                    new FileOutputStream(args[0]),
                    StandardCharsets.UTF_8
                )
            )
        ) {
            out.write("{\"program\":");
            out.write(quote(currentProgram.getName()));
            out.write(",\"functions\":[");

            while (
                it.hasNext() &&
                count < MAX_FUNCTIONS
            ) {
                monitor.checkCancelled();

                Function f = it.next();

                if (count > 0) out.write(",");

                String address =
                    f.getEntryPoint().toString();

                out.write("{\"name\":");
                out.write(quote(f.getName()));
                out.write(",\"address\":");
                out.write(quote(address));

                if (pseudocodeCount < MAX_PSEUDOCODE) {
                    try {
                        DecompileResults r =
                            decompiler.decompileFunction(
                                f, 12, monitor
                            );

                        if (
                            r != null &&
                            r.decompileCompleted() &&
                            r.getDecompiledFunction() != null
                        ) {
                            String code =
                                r.getDecompiledFunction().getC();

                            if (code != null) {
                                if (code.length() > 6000) {
                                    code = code.substring(0, 6000);
                                }
                                out.write(",\"pseudocode\":");
                                out.write(quote(code));
                                pseudocodeCount++;
                            }
                        }
                    } catch (Exception e) {
                        printerr(
                            "Decompiler warning: " +
                            f.getName()
                        );
                    }
                }

                out.write("}");

                if (calls.size() < MAX_CALLS) {
                    try {
                        Set<Function> targets =
                            f.getCalledFunctions(monitor);

                        int localCount = 0;

                        for (Function target : targets) {
                            if (
                                calls.size() >= MAX_CALLS ||
                                localCount >= MAX_CALLS_PER_FUNCTION
                            ) break;

                            String dest =
                                target.getEntryPoint().toString();

                            String key = address + ">" + dest;

                            if (seen.add(key)) {
                                String entry =
                                    "{\"source_address\":" +
                                    quote(address) +
                                    ",\"source_name\":" +
                                    quote(f.getName()) +
                                    ",\"target_address\":" +
                                    quote(dest) +
                                    ",\"target_name\":" +
                                    quote(target.getName()) +
                                    "}";

                                calls.add(entry);
                            }
                            localCount++;
                        }
                    } catch (Exception e) {
                        printerr(
                            "Call graph warning: " +
                            f.getName()
                        );
                    }
                }

                count++;
            }

            boolean remaining = it.hasNext();

            out.write("],\"calls\":[");

            for (int i = 0; i < calls.size(); i++) {
                if (i > 0) out.write(",");
                out.write(calls.get(i));
            }

            out.write("],\"metadata\":{");
            out.write("\"functions_exported\":" + count);
            out.write(",\"pseudocode_exported\":" + pseudocodeCount);
            out.write(",\"calls_exported\":" + calls.size());
            out.write(",\"functions_truncated\":" + remaining);
            out.write(",\"limits\":{\"functions\":2000");
            out.write(",\"pseudocode\":60");
            out.write(",\"calls\":3000}}}");

        } finally {
            decompiler.dispose();
        }

        println(
            "Export complete: functions=" + count +
            ", pseudocode=" + pseudocodeCount +
            ", calls=" + calls.size()
        );
    }
}
