// @category ESP32C3
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.BufferedWriter;
import java.util.*;

public class CandidateDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] argv = getScriptArgs();
        if (argv.length != 2) throw new IllegalArgumentException("EXPECTED: TSV_IN TSV_OUT");
        List<String> rows = Files.readAllLines(Path.of(argv[0]), StandardCharsets.UTF_8);
        DecompInterface iface = new DecompInterface();
        iface.setSimplificationStyle("decompile");
        if (!iface.openProgram(currentProgram)) throw new IllegalStateException("DECOMPILER_OPEN_FAILED");
        int ok=0, missing=0, errors=0;
        try (BufferedWriter out=Files.newBufferedWriter(Path.of(argv[1]),StandardCharsets.UTF_8)) {
            out.write("name\taddress\tstatus\tfunction_entry\tfunction_name\tbody_address_count\tdecompilation_base64\terror_base64\n");
            for (String row: rows) {
                if (row.isBlank()) continue;
                String[] parts=row.split("\\t");
                if (parts.length!=2) throw new IllegalStateException("INVALID_CANDIDATE_ROW:"+row);
                String name=parts[0],address=parts[1];
                String status="NO_FUNCTION", decompiled="", error="", entry="", resolved="";
                long bodyCount=0;
                try {
                    Address addr=toAddr(Long.decode(address));
                    Function f=currentProgram.getFunctionManager().getFunctionAt(addr);
                    if (f==null) f=currentProgram.getFunctionManager().getFunctionContaining(addr);
                    if (f!=null) {
                        entry=f.getEntryPoint().toString();resolved=f.getName();bodyCount=f.getBody().getNumAddresses();
                        DecompileResults result=iface.decompileFunction(f,25,monitor);
                        if (result.decompileCompleted() && result.getDecompiledFunction()!=null) {
                            decompiled=result.getDecompiledFunction().getC();status="DECOMPILED";ok++;
                        } else {status="DECOMPILER_FAILURE";error=result.getErrorMessage();errors++;}
                    } else missing++;
                } catch (Exception ex) { status="EXCEPTION";error=ex.toString();errors++; }
                String c64=Base64.getEncoder().encodeToString(decompiled.getBytes(StandardCharsets.UTF_8));
                String e64=Base64.getEncoder().encodeToString(error.getBytes(StandardCharsets.UTF_8));
                out.write(String.join("\t",name,address,status,entry,resolved,Long.toString(bodyCount),c64,e64)+"\n");
                out.flush();
            }
        } finally {iface.dispose();}
        println("GHIDRA_CANDIDATE_DECOMPILATION_SUMMARY ok="+ok+" missing="+missing+" errors="+errors+" total="+rows.size());
    }
}
