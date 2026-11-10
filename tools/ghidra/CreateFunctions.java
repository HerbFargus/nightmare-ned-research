// Create a function at every address listed (hex, one per line) in a file, then let the analyser
// follow them. Used with tools/find_starts.py for functions only reached through pointers.
//@category NightmarenedM0
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

import java.nio.file.Files;
import java.nio.file.Paths;

public class CreateFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        int made = 0, had = 0, failed = 0;
        for (String line : Files.readAllLines(Paths.get(getScriptArgs()[0]))) {
            line = line.trim();
            if (line.isEmpty()) continue;
            Address a = toAddr(Long.parseLong(line, 16));
            if (getFunctionAt(a) != null) { had++; continue; }
            disassemble(a);
            if (createFunction(a, null) != null) made++; else failed++;
        }
        analyzeChanges(currentProgram);
        println("CreateFunctions: made " + made + ", already " + had + ", failed " + failed);
    }
}
