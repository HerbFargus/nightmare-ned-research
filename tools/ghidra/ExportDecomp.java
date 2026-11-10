// Decompile every function to out\decomp\<entry>.c, each headed by its name, plate comment, callers and
// callees, and write out\callgraph.csv (caller,callee). The naming pass reads these.
//   analyzeHeadless out\ghidra Bomberman -process bm95.exe -noanalysis -readOnly -scriptPath tools
//       -postScript ExportDecomp.java out
//@category NightmarenedM0
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

import java.io.File;
import java.io.PrintWriter;
import java.util.Set;

public class ExportDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        File out = new File(getScriptArgs()[0]);
        File dir = new File(out, "decomp");
        dir.mkdirs();
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        int n = 0, failed = 0;
        try (PrintWriter graph = new PrintWriter(new File(out, "callgraph.csv"), "UTF-8")) {
            graph.println("caller,callee");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isExternal()) continue;
                Set<Function> callers = f.getCallingFunctions(monitor), callees = f.getCalledFunctions(monitor);
                for (Function c : callees)
                    if (!c.isExternal()) graph.printf("%x,%x%n", f.getEntryPoint().getOffset(), c.getEntryPoint().getOffset());
                StringBuilder head = new StringBuilder();
                head.append("// ").append(f.getName()).append(" @ ").append(f.getEntryPoint())
                    .append("  size ").append(f.getBody().getNumAddresses()).append('\n');
                if (f.getComment() != null) head.append("// ").append(f.getComment().replace('\n', ' ')).append('\n');
                head.append("// callers:");
                for (Function c : callers) head.append(' ').append(c.getName());
                head.append("\n// callees:");
                for (Function c : callees) head.append(' ').append(c.getName());
                head.append('\n');
                DecompileResults r = d.decompileFunction(f, 60, monitor);
                String body = r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed: " + r.getErrorMessage() + "\n";
                if (!r.decompileCompleted()) failed++;
                try (PrintWriter w = new PrintWriter(new File(dir, String.format("%x.c", f.getEntryPoint().getOffset())), "UTF-8")) {
                    w.print(head);
                    w.print(body);
                }
                n++;
            }
        }
        println("ExportDecomp: " + n + " functions (" + failed + " failed) -> " + dir);
    }
}
