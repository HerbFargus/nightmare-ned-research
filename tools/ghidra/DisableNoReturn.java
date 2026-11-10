// Pre-analysis: stop Ghidra from inferring non-returning functions. It wrongly decides
// that 0x430850 (slot_place_x) never returns and cuts the code after 408 calls.
//@category NightmarenedM0
import ghidra.app.script.GhidraScript;

public class DisableNoReturn extends GhidraScript {
    @Override
    public void run() throws Exception {
        setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
        println("DisableNoReturn: done");
    }
}
