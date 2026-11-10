// Clears a wrong no-return flag (args: hex addresses), re-disassembles the code that was
// cut off after every call to it, and refits the bodies of the functions holding those calls.
//@category NightmarenedM0
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

import java.util.HashSet;
import java.util.Set;

public class FixNoReturn extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String arg : getScriptArgs()) {
            Address target = toAddr(Long.parseLong(arg, 16));
            Function f = getFunctionAt(target);
            if (f == null) { println("no function at " + arg); continue; }
            f.setNoReturn(false);
            Set<Function> touched = new HashSet<>();
            int calls = 0;
            for (Reference ref : getReferencesTo(target)) {
                if (!ref.getReferenceType().isCall()) continue;
                Instruction insn = getInstructionAt(ref.getFromAddress());
                if (insn == null) continue;
                if (insn.getFlowOverride() == FlowOverride.CALL_RETURN) insn.setFlowOverride(FlowOverride.NONE);
                insn.setFallThrough(insn.getDefaultFallThrough());
                Address next = insn.getDefaultFallThrough();
                if (next != null && getInstructionAt(next) == null) disassemble(next);
                Function owner = getFunctionContaining(ref.getFromAddress());
                if (owner != null) touched.add(owner);
                calls++;
            }
            analyzeChanges(currentProgram);
            int fixed = 0;
            for (Function owner : touched) {
                if (CreateFunctionCmd.fixupFunctionBody(currentProgram, owner, monitor)) fixed++;
            }
            println("FixNoReturn " + arg + ": " + calls + " calls, " + touched.size() + " functions, " + fixed + " refitted");
        }
    }
}
