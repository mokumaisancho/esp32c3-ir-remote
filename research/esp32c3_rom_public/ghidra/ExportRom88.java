// Ghidra 12.1.4 headless postscript. Uses exact vendor-ROM ELF addresses from prior audit.
// Decompiled C is a hypothesis, not proof of executed hardware behavior.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;

public class ExportRom88 extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("EXPECTED: function.tsv output.tsv");
        }
        List<String> lines = Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8);
        if (lines.size() != 88) throw new IllegalArgumentException("NOT_88_CANDIDATES: " + lines.size());
        DecompInterface dec = new DecompInterface();
        if (!dec.openProgram(currentProgram)) throw new IllegalStateException("GHIDRA_DECOMPILER_OPEN_FAILED");
        List<String> result = new ArrayList<>();
        int matched = 0, completed = 0, absent = 0, mismatch = 0, failed = 0;
        for (String line : lines) {
            String[] fields = line.split("\t", -1);
            if (fields.length != 2 || fields[0].isEmpty()) throw new IllegalArgumentException("MALFORMED_NAME_ADDRESS_TSV");
            String name = fields[0], addressText = fields[1];
            String status = "UNKNOWN", actualName = "", actualAddress = "", pseudoC = "";
            if ("ABSENT".equals(addressText)) {
                status = "ABSENT_ELF_FUNCTION";
                absent++;
            } else {
                Address address = currentProgram.getAddressFactory().getAddress(addressText);
                if (address == null) throw new IllegalArgumentException("INVALID_ELF_ADDRESS: " + addressText);
                Function func = currentProgram.getFunctionManager().getFunctionAt(address);
                if (func == null) {
                    status = "NO_GHIDRA_FUNCTION_AT_OFFICIAL_ENTRY";
                    mismatch++;
                } else {
                    matched++;
                    actualName = func.getName();
                    actualAddress = func.getEntryPoint().toString();
                    DecompileResults dr = dec.decompileFunction(func, 20, monitor);
                    if (dr != null && dr.decompileCompleted() && dr.getDecompiledFunction() != null) {
                        pseudoC = dr.getDecompiledFunction().getC();
                        status = "DECOMPILATION_COMPLETED_UNVALIDATED";
                        completed++;
                    } else {
                        status = "DECOMPILATION_FAILED_OR_TIMED_OUT";
                        failed++;
                    }
                }
            }
            String encoded = Base64.getEncoder().encodeToString(pseudoC.getBytes(StandardCharsets.UTF_8));
            result.add(name + "\t" + addressText + "\t" + status + "\t" + actualName + "\t" + actualAddress + "\t" + encoded);
        }
        Files.write(Path.of(args[1]), result, StandardCharsets.UTF_8);
        dec.dispose();
        println("GHIDRA_88_EXPORT_SUMMARY matched=" + matched + " decompiled=" + completed +
            " absent=" + absent + " wrong_entry=" + mismatch + " failed=" + failed +
            " name_of_loaded_program=" + currentProgram.getName());
        if (matched + absent + mismatch != 88) throw new IllegalStateException("GHIDRA_ROWS_DROPPED");
    }
}
