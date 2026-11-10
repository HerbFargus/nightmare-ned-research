// Write every function as entry,end,size,name,callers,callees to a CSV (default out\functions.csv),
// for the Python passes (module map, call-convention fix-ups).
//@category NightmarenedM0
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

import java.io.PrintWriter;

public class ExportFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String path = args.length > 0 ? args[0] : "out/functions.csv";
        int n = 0;
        try (PrintWriter out = new PrintWriter(path, "UTF-8")) {
            out.println("entry,end,size,name,convention,callers,callees");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isExternal() || f.isThunk() && f.getBody().getNumAddresses() == 0) continue;
                long lo = f.getBody().getMinAddress().getOffset(), hi = f.getBody().getMaxAddress().getOffset();
                out.printf("%x,%x,%d,%s,%s,%d,%d%n", f.getEntryPoint().getOffset(), hi + 1,
                    f.getBody().getNumAddresses(), f.getName(), f.getCallingConventionName(),
                    f.getCallingFunctions(monitor).size(), f.getCalledFunctions(monitor).size());
                n++;
            }
        }
        println("ExportFunctions: " + n + " functions -> " + path);
    }
}
