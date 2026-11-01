package com.xebyte.core;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Resolves API-name hashes by executing the sample's own hash code over
 * candidate names read from real DLL export tables on disk.
 *
 * <p>Candidates are parsed here from a corpus directory; there is no
 * candidate-list parameter. The caller supplies the location of the hash
 * code and how to reach it, and that code is executed rather than
 * reimplemented.</p>
 *
 * <p>The hash code is a region with an input state, not necessarily a cdecl
 * function. It may be entered through a stack frame and run to its return,
 * or take arguments in named registers, or be a loop inlined in a larger
 * function bounded by an explicit stop address.</p>
 *
 * @since 7.0.0
 */
@McpToolGroup(value = "emulation",
        description = "API hash resolution against real export tables by executing "
                + "the sample's own hash code")
public class HashResolverService {

    private static final long STACK     = 0x00300000L;
    private static final long SCRATCH   = 0x00320000L;
    private static final long SENTINEL  = 0x00BADBADL;
    private static final int  MAX_STEPS = 100_000;
    private static final int  MAX_MODULES = 64;

    // LockBit 3.0 enumerates System32 for "*.dll" and again for "*.drv".
    private static final String CORPUS_GLOB = "*.{dll,drv}";

    // A degenerate run puts every candidate in one bucket; cap the detail.
    private static final int MAX_COLLISION_BUCKETS = 20;
    private static final int MAX_NAMES_PER_BUCKET  = 8;

    // A module may hold many unhashable names, so count rather than list them.
    private static final int MAX_SKIPPED_EXAMPLES = 5;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public HashResolverService(ProgramProvider programProvider,
                               ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    /** One target hash and what is known about it. */
    private static final class Target {
        long    hash;
        String  expected;   // null when unknown or unscored
        String  module;     // resolving module, when known
        boolean unknown;    // no published name; a resolution is a recovery
        boolean used;       // the sample reads this target's output slot
        String  address;    // use site, when supplied, for the annotation list
    }

    /** Everything needed to run one role's hash code on one name. */
    private static final class HashSpec {
        long   entry;                   // function entry, or first address of a region
        long   stopAt;                  // last address plus one; 0 runs to the return
        List<String> stackArgs;         // push order, rightmost argument first
        Map<String, String> regArgs;    // register name to token
        Map<String, String> frameArgs;  // frame-pointer offset to token
        String enc;
        String fold;
        byte[] charMap;                 // per-character normaliser, when cached
        long   normStringFunc;          // whole-string normaliser, when supplied
        String resultReg;
        int    bits;                    // 32 or 64, from the loaded program
        long   mask;                    // hash width, independent of the bitness
    }

    /** Stack mechanics follow the loaded program's pointer width, not the algorithm. */
    private static String spReg(int bits)   { return bits == 64 ? "RSP" : "ESP"; }
    private static String bpReg(int bits)   { return bits == 64 ? "RBP" : "EBP"; }
    private static String defaultRet(int bits) { return bits == 64 ? "RAX" : "EAX"; }

    @McpTool(path = "/resolve_api_hashes", method = "POST",
            description = "Resolve API name hashes by executing the sample's own hash "
                    + "code over candidate names read from real DLL export tables. "
                    + "Unlike brute-force emulation, no candidate list is supplied: name a "
                    + "DLL directory and module scope and the export tables are parsed here. "
                    + "The hash code may be a cdecl function, a function taking its argument "
                    + "in a register, or a loop inlined in a larger function with no entry "
                    + "point and no return. Seeded, unseeded, ASCII and UTF-16 schemes are "
                    + "parameters, so undocumented or per-build mutated hashes work unchanged.",
            category = "emulation")
    public Response resolveApiHashes(

            @Param(value = "hash_func", paramType = "address", source = ParamSource.BODY,
                    description = "Where the export-name hash code starts, e.g. 0x00401096. "
                            + "Normally a function entry. When hash_end is also given this is "
                            + "the first address of an inlined region instead, which need not "
                            + "be a function at all.")
            String hashFuncAddr,

            @Param(value = "dll_dir", source = ParamSource.BODY,
                    description = "Directory holding the DLL corpus that candidate names are "
                            + "read from. Use 32-bit DLLs (SysWOW64) for a 32-bit sample.")
            String dllDir,

            @Param(value = "targets", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "",
                    description = "JSON array of hashes to look up, one string each. Formats: "
                            + "\"0xa0e931df\" (hash only), "
                            + "\"0xa0e931df ntdll!RtlAllocateHeap\" (known name), "
                            + "\"0xa0e931df ntdll!?\" (module known, name not published), "
                            + "\"0xa0e931df ?\" (nothing known). The module qualifier matters "
                            + "for unseeded schemes, where the same export name in two DLLs "
                            + "hashes identically. Pass values already in the form the sample "
                            + "compares against: a stored constant that is masked or encrypted "
                            + "is decoded by the caller, not here. Omit to return the whole "
                            + "table.")
            String targetsJson,

            @Param(value = "module_hash_func", paramType = "address", source = ParamSource.BODY,
                    defaultValue = "0",
                    description = "Where the module-name hash code starts, or 0 if one routine "
                            + "does both. Supply it even when the sample does not seed with it: "
                            + "reproducing the published module constants is what verifies the "
                            + "transcription is correct.")
            String moduleHashFuncAddr,

            @Param(value = "hash_end", paramType = "address", source = ParamSource.BODY,
                    defaultValue = "0",
                    description = "Stop address for an inlined export-name hash, or 0 when "
                            + "hash_func is a function to run to its return. Emulation halts "
                            + "when the program counter reaches this address, which is "
                            + "therefore the first address NOT executed. Use this when the hash "
                            + "loop sits inside a larger function with no entry point and no "
                            + "RET of its own, and set it to the address just past the loop so "
                            + "the surrounding code does not run. Read result_reg from the "
                            + "accumulator the loop uses rather than from a return convention.")
            String hashEndAddr,

            @Param(value = "module_hash_end", paramType = "address", source = ParamSource.BODY,
                    defaultValue = "0",
                    description = "Same as hash_end, for the module-name hash.")
            String moduleHashEndAddr,

            @Param(value = "args", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "[\"NAME\"]",
                    description = "JSON array giving the stack push order for hash_func, "
                            + "rightmost argument first. Tokens: \"NAME\" (pointer to "
                            + "the candidate string), \"SEED\", \"LEN\", \"LEN_BYTES\", or a "
                            + "literal integer such as \"0\". LEN counts encoding units, so "
                            + "characters, and LEN_BYTES counts bytes. The two differ only "
                            + "under UTF16, where they differ by a factor of two, and samples "
                            + "disagree about which their routine wants: NetWalker passes a "
                            + "character count and Latrodectus a byte count (wcslen<<1). Read "
                            + "which one off the call site rather than assuming. "
                            + "For a 32-bit cdecl hash(name, len, fold) pass "
                            + "[\"0\", \"0\", \"NAME\"]. Pass [] when nothing is on the stack "
                            + "and every input is in a register, which is the usual case for a "
                            + "64-bit sample, where the first four arguments go in RCX, RDX, R8 "
                            + "and R9 through arg_regs and only a fifth argument onward reaches "
                            + "the stack. Slot width, shadow space and alignment follow the "
                            + "loaded program and are not configured here.")
            String argsJson,

            @Param(value = "module_args", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "[\"NAME\"]",
                    description = "Same as args, for module_hash_func.")
            String moduleArgsJson,

            @Param(value = "arg_regs", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "{}",
                    description = "JSON object placing export-name hash inputs in registers "
                            + "rather than on the stack, e.g. {\"ECX\": \"NAME\"} for a 32-bit "
                            + "__fastcall routine, {\"RCX\": \"NAME\"} for the 64-bit Microsoft "
                            + "convention, or {\"EDX\": \"NAME\", \"ECX\": \"SEED\"} for an "
                            + "inlined loop that reads its pointer from EDX and accumulates in "
                            + "ECX. Keys are register names, values are the same tokens args "
                            + "takes. Registers are written after the stack pointer and frame "
                            + "pointer are set up and before execution starts, so naming either "
                            + "overrides it. Combine with args when a routine takes some "
                            + "arguments each way. Given explicitly here rather than read from "
                            + "a calling convention committed in Ghidra, so that the request "
                            + "alone is enough to replay the run.")
            String argRegsJson,

            @Param(value = "module_arg_regs", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "{}",
                    description = "Same as arg_regs, for the module-name hash. A sample may "
                            + "pass the two roles differently, one on the stack and one in a "
                            + "register.")
            String moduleArgRegsJson,

            @Param(value = "seed_mode", source = ParamSource.BODY, defaultValue = "NONE",
                    description = "NONE, FIXED, or MODULE_HASH when the module hash seeds the "
                            + "API hash. Seeding namespaces the hash by module, so seeded "
                            + "schemes cannot alias across DLLs and unseeded ones can.")
            String seedMode,

            @Param(value = "seed_value", source = ParamSource.BODY, defaultValue = "0",
                    description = "Seed constant used when seed_mode is FIXED.")
            String seedValueStr,

            @Param(value = "encoding", source = ParamSource.BODY, defaultValue = "ASCII",
                    description = "ASCII or UTF16, for export names.")
            String encoding,

            @Param(value = "module_encoding", source = ParamSource.BODY, defaultValue = "ASCII",
                    description = "ASCII or UTF16, for module names. Often differs from the "
                            + "export-name encoding in the same sample.")
            String moduleEncoding,

            @Param(value = "fold_case", source = ParamSource.BODY, defaultValue = "false",
                    description = "Case folding applied to export names before hashing: "
                            + "none, lower or upper. Accepts false for none and true for "
                            + "lower. Set none when the sample folds case itself via an "
                            + "argument flag or inside the hash code.")
            String foldCase,

            @Param(value = "module_fold_case", source = ParamSource.BODY, defaultValue = "false",
                    description = "Same as fold_case, for module names. A sample may fold "
                            + "the two in opposite directions.")
            String moduleFoldCase,

            @Param(value = "normalize_func", paramType = "address", source = ParamSource.BODY,
                    defaultValue = "0",
                    description = "Address of the sample's own name-normalising function, or 0 "
                            + "if none. When a sample transforms a name before hashing, that "
                            + "transform is its code and is executed rather than described. "
                            + "Use instead of fold_case whenever the transform is reachable as "
                            + "a function, which covers transforms fold_case cannot express.")
            String normalizeFuncAddr,

            @Param(value = "normalize_mode", source = ParamSource.BODY, defaultValue = "STRING",
                    description = "Shape of normalize_func. STRING for f(char* s) rewriting the "
                            + "buffer in place. CHAR for f(int c) returning one byte, which is "
                            + "executed once per byte value and cached.")
            String normalizeMode,

            @Param(value = "module_normalize_func", paramType = "address",
                    source = ParamSource.BODY, defaultValue = "0",
                    description = "Same as normalize_func, for module names. A sample may "
                            + "normalise the two roles differently.")
            String moduleNormalizeFuncAddr,

            @Param(value = "module_normalize_mode", source = ParamSource.BODY,
                    defaultValue = "STRING",
                    description = "Same as normalize_mode, for module names.")
            String moduleNormalizeMode,

            @Param(value = "include_nul", source = ParamSource.BODY, defaultValue = "false",
                    description = "Whether an explicit LEN argument counts the terminating NUL. "
                            + "The terminator is always written to memory regardless, since a "
                            + "sample that computes length with strlen needs it present.")
            boolean includeNul,

            @Param(value = "result_reg", source = ParamSource.BODY, defaultValue = "",
                    description = "Register holding the hash when execution stops. Read this "
                            + "from the function epilogue rather than assuming the return "
                            + "register; some samples return in EDX. For an inlined region "
                            + "bounded by hash_end there is no return convention at all, so "
                            + "read it from the accumulator the loop uses. Defaults to EAX for "
                            + "a 32-bit program and RAX for a 64-bit one.")
            String resultReg,

            @Param(value = "module_result_reg", source = ParamSource.BODY, defaultValue = "",
                    description = "Same as result_reg, for the module-name hash, when the two "
                            + "roles leave their result in different registers. Defaults to "
                            + "result_reg. Needed where one role is a function returning in the "
                            + "return register and the other is an inlined loop accumulating "
                            + "somewhere else.")
            String moduleResultReg,

            @Param(value = "frame_args", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "{}",
                    description = "JSON object placing values in the caller's frame, as offsets "
                            + "from the frame pointer, e.g. {\"0xc\": \"SEED\"}. Needed when an "
                            + "inlined region bounded by hash_end reads something the enclosing "
                            + "function was passed, such as a per-call-site key XORed into the "
                            + "result before the comparison. Including that instruction in the "
                            + "region and supplying what it reads lets the sample's own code do "
                            + "the work, so stored constants can be passed as targets exactly as "
                            + "they appear in the listing, with no decoding by hand. Keys are "
                            + "signed offsets in hex or decimal, values are the same tokens args "
                            + "takes. Writes happen after the frame pointer is set.")
            String frameArgsJson,

            @Param(value = "module_frame_args", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "{}",
                    description = "Same as frame_args, for the module-name hash.")
            String moduleFrameArgsJson,

            @Param(value = "names", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "[]",
                    description = "JSON array of export names to hash and report, the reverse of "
                            + "targets. Use it to ask what a known name hashes to under these "
                            + "parameters, then look for that value in the listing. Without it "
                            + "the only direction available is listing to corpus, so a target "
                            + "set that is wrong looks the same as a corpus that is missing "
                            + "names. Each name is reported under both the export and module "
                            + "roles. When names is given and targets is empty the corpus sweep "
                            + "is skipped, so the call returns at once.")
            String namesJson,

            @Param(value = "addresses", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "[]",
                    description = "JSON array of use-site addresses, one per entry of targets and "
                            + "in the same order. When given, the result carries an annotations "
                            + "list of address and comment pairs ready to hand to a comment-"
                            + "writing tool. The resolver does not modify the program, it only "
                            + "pairs each name with the address the caller supplied, which "
                            + "removes the hand transcription step between two tools. That step "
                            + "is where a mismatched row is most likely, and it does not announce "
                            + "itself when it happens.")
            String addressesJson,

            @Param(value = "corpus_manifest", source = ParamSource.BODY, defaultValue = "false",
                    description = "Report each corpus module's size, SHA-256 and PE build "
                            + "timestamp alongside its row. The corpus is the answer key, so "
                            + "which build it came from is part of the result rather than "
                            + "context the reader has to be told separately. Costs one digest "
                            + "per module over bytes already in memory.")
            boolean corpusManifest,

            @Param(value = "hash_bits", source = ParamSource.BODY, defaultValue = "32",
                    description = "Width of the hash value itself, 32 or 64. This is a property "
                            + "of the algorithm and not of the sample's bitness: a 64-bit "
                            + "sample normally still computes a 32-bit hash, so the default is "
                            + "32 either way. Set 64 only where the sample compares a full "
                            + "64-bit value, which also widens how targets are printed.")
            String hashBitsStr,

            @Param(value = "scope", source = ParamSource.BODY, fieldsJson = true,
                    defaultValue = "[]",
                    description = "JSON array of module file names to enumerate, e.g. "
                            + "[\"ntdll.dll\", \"kernel32.dll\"]. Omit for every DLL in dll_dir. "
                            + "Scope affects correctness for unseeded schemes, not just speed.")
            String scopeJson,

            @Param(value = "program", defaultValue = "")
            String programName) {

        ServiceUtils.ProgramOrError pe =
                ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address hashFn = ServiceUtils.parseAddress(program, hashFuncAddr);
        if (hashFn == null) return Response.err(ServiceUtils.getLastParseError());

        long moduleHashFunc, hashEnd, moduleHashEnd;
        long normalizeFunc, moduleNormalizeFunc;
        try {
            moduleHashFunc      = optionalAddress(program, moduleHashFuncAddr);
            hashEnd             = optionalAddress(program, hashEndAddr);
            moduleHashEnd       = optionalAddress(program, moduleHashEndAddr);
            normalizeFunc       = optionalAddress(program, normalizeFuncAddr);
            moduleNormalizeFunc = optionalAddress(program, moduleNormalizeFuncAddr);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (hashEnd != 0 && hashEnd <= hashFn.getOffset())
            return Response.err("hash_end must be above hash_func: hash_end is the first "
                    + "address not executed, so it sits just past the hash loop.");
        if (moduleHashEnd != 0 && moduleHashFunc != 0 && moduleHashEnd <= moduleHashFunc)
            return Response.err("module_hash_end must be above module_hash_func.");

        long seedValue;
        try {
            seedValue = parseLongValue(seedValueStr);
        } catch (Exception e) {
            return Response.err("Invalid seed_value: " + seedValueStr);
        }

        if (dllDir == null || dllDir.isBlank())
            return Response.err("dll_dir is required: candidate names are read from real "
                    + "export tables, not supplied as a list.");
        Path corpus;
        try {
            corpus = Paths.get(dllDir);
        } catch (Exception e) {
            return Response.err("Invalid dll_dir: " + dllDir);
        }
        if (!Files.isDirectory(corpus))
            return Response.err("dll_dir is not a directory: " + dllDir);

        List<String> argSpec       = parseStringArray(argsJson,       List.of("NAME"));
        List<String> moduleArgSpec = parseStringArray(moduleArgsJson, List.of("NAME"));
        List<String> scope         = parseStringArray(scopeJson,      List.of());
        List<String> targetSpecs   = parseStringArray(targetsJson,    List.of());

        Map<String, String> argRegs       = parseStringMap(argRegsJson);
        Map<String, String> moduleArgRegs = parseStringMap(moduleArgRegsJson);
        Map<String, String> frameArgs       = parseStringMap(frameArgsJson);
        Map<String, String> moduleFrameArgs = parseStringMap(moduleFrameArgsJson);
        List<String> probeNames = parseStringArray(namesJson, List.of());
        List<String> addresses  = parseStringArray(addressesJson, List.of());

        if (argSpec.isEmpty() && argRegs.isEmpty())
            return Response.err("hash_func receives nothing: give the candidate pointer "
                    + "either on the stack through args or in a register through arg_regs.");

        String seed = seedMode == null ? "NONE" : seedMode.trim().toUpperCase();
        if (!seed.equals("NONE") && !seed.equals("FIXED") && !seed.equals("MODULE_HASH"))
            return Response.err("seed_mode must be NONE, FIXED or MODULE_HASH");

        String enc    = encoding == null ? "ASCII" : encoding.trim().toUpperCase();
        String modEnc = moduleEncoding == null ? "ASCII" : moduleEncoding.trim().toUpperCase();

        int programBits = program.getDefaultPointerSize() * 8;
        if (programBits != 32 && programBits != 64)
            return Response.err("Unsupported pointer size: " + programBits + " bits");

        String resReg = (resultReg == null || resultReg.isBlank())
                ? defaultRet(programBits) : resultReg.trim().toUpperCase();
        String modResReg = (moduleResultReg == null || moduleResultReg.isBlank())
                ? resReg : moduleResultReg.trim().toUpperCase();

        int hashBits;
        try {
            hashBits = (hashBitsStr == null || hashBitsStr.isBlank())
                    ? 32 : Integer.parseInt(hashBitsStr.trim());
        } catch (Exception e) {
            return Response.err("Invalid hash_bits: " + hashBitsStr);
        }
        if (hashBits != 32 && hashBits != 64)
            return Response.err("hash_bits must be 32 or 64");
        long hashMask = (hashBits == 64) ? -1L : 0xFFFFFFFFL;

        List<String> modules = scope.isEmpty() ? listCorpus(corpus) : scope;
        if (modules.isEmpty())
            return Response.err("No DLLs found in " + dllDir);
        if (modules.size() > MAX_MODULES)
            return Response.err("Too many modules (max " + MAX_MODULES + ")");

        List<Target> targets = parseTargets(targetSpecs);
        if (!addresses.isEmpty() && addresses.size() != targets.size())
            return Response.err("addresses has " + addresses.size() + " entries but targets has "
                    + targets.size() + ". They are matched by position, so a partial list would "
                    + "silently attach names to the wrong addresses.");
        for (int i = 0; i < addresses.size(); i++) targets.get(i).address = addresses.get(i);

        // Audit trail: Ghidra console, Ghidra log, and a file beside the corpus.
        String invoke = String.format(
                "[HashResolver] INVOKE program=%s hash=0x%X..0x%X module_hash=0x%X..0x%X "
                + "bits=%d hash_bits=%d seed=%s enc=%s/%s fold=%s/%s norm=0x%X:%s/0x%X:%s nul=%s reg=%s/%s "
                + "args=%s module_args=%s arg_regs=%s module_arg_regs=%s frame_args=%s module_frame_args=%s names=%d "
                + "dll_dir=%s scope=%s targets=%d",
                program.getName(), hashFn.getOffset(), hashEnd, moduleHashFunc, moduleHashEnd,
                programBits, hashBits, seed, enc, modEnc, foldCase, moduleFoldCase,
                normalizeFunc, normalizeMode, moduleNormalizeFunc, moduleNormalizeMode,
                includeNul, resReg, modResReg, argSpec, moduleArgSpec, argRegs, moduleArgRegs,
                frameArgs, moduleFrameArgs, probeNames.size(),
                dllDir, modules, targets.size());
        Msg.info(this, invoke);
        audit(corpus, invoke);

        Map<Long, List<String>> table = new LinkedHashMap<>();
        List<Map<String, Object>> moduleRows = new ArrayList<>();
        Map<String, Object> result = new LinkedHashMap<>();

        int hashed = 0, missing = 0, bitnessMismatch = 0;
        // Separate from `missing` so modules_resolved counts modules actually swept.
        int errored = 0, skippedTotal = 0;
        long start = System.currentTimeMillis();
        TaskMonitor monitor = new ConsoleTaskMonitor();

        // One emulator for the whole sweep. See EmuHolder for why.
        EmuHolder holder = new EmuHolder(program);

        // A per-character normaliser is a byte-to-byte map: run it once per value.
        byte[] charMap = null, moduleCharMap = null;
        long normStringFunc = 0, moduleNormStringFunc = 0;
        try {
            if (normalizeFunc != 0) {
                if ("CHAR".equalsIgnoreCase(normalizeMode))
                    charMap = charTable(program, monitor, normalizeFunc, resReg, programBits);
                else normStringFunc = normalizeFunc;
            }
            if (moduleNormalizeFunc != 0) {
                if ("CHAR".equalsIgnoreCase(moduleNormalizeMode))
                    moduleCharMap = charTable(program, monitor, moduleNormalizeFunc, resReg,
                            programBits);
                else moduleNormStringFunc = moduleNormalizeFunc;
            }
        } catch (Exception e) {
            return Response.err("normalize_func failed: " + e.getMessage());
        }

        HashSpec api = new HashSpec();
        api.entry = hashFn.getOffset();
        api.stopAt = hashEnd;
        api.stackArgs = argSpec;
        api.regArgs = argRegs;
        api.frameArgs = frameArgs;
        api.enc = enc;
        api.fold = foldCase;
        api.charMap = charMap;
        api.normStringFunc = normStringFunc;
        api.resultReg = resReg;
        api.bits = programBits;
        api.mask = hashMask;

        // The module role falls back to the API role when one routine serves both.
        HashSpec mod = new HashSpec();
        mod.entry = (moduleHashFunc != 0) ? moduleHashFunc : api.entry;
        mod.stopAt = (moduleHashFunc != 0) ? moduleHashEnd : hashEnd;
        mod.stackArgs = moduleArgSpec;
        mod.regArgs = moduleArgRegs.isEmpty() && moduleHashFunc == 0 ? argRegs : moduleArgRegs;
        mod.frameArgs = moduleFrameArgs.isEmpty() && moduleHashFunc == 0
                ? frameArgs : moduleFrameArgs;
        mod.enc = modEnc;
        mod.fold = moduleFoldCase;
        mod.charMap = moduleCharMap;
        mod.normStringFunc = moduleNormStringFunc;
        mod.resultReg = modResReg;
        mod.bits = programBits;
        mod.mask = hashMask;

        // Reverse lookup: what a known name hashes to.
        if (!probeNames.isEmpty()) {
            List<String> rows = new ArrayList<>();
            for (String n : probeNames) {
                String a, m;
                try {
                    a = hex(callHash(program, monitor, api, n, seedValue, includeNul, holder), hashMask);
                } catch (Exception e) { a = "error: " + e.getMessage(); }
                try {
                    m = hex(callHash(program, monitor, mod, n, seedValue, includeNul, holder), hashMask);
                } catch (Exception e) { m = "error: " + e.getMessage(); }
                rows.add(n + "  export=" + a + "  module=" + m);
            }
            result.put("name_hashes", rows);
            for (String r : rows) audit(corpus, "[HashResolver] NAME " + r);
            if (targets.isEmpty()) {
                result.put("program", program.getName());
                result.put("program_bits", programBits);
                result.put("hash_bits", hashBits);
                result.put("note", "names given and targets empty, so the corpus was not swept");
                holder.discard();
                return Response.ok(result);
            }
        }

        for (String dll : modules) {
            byte[] image;
            try {
                image = Files.readAllBytes(corpus.resolve(dll));
            } catch (Exception e) {
                moduleRows.add(row(dll, "missing", null, null, 0, null));
                missing++;
                continue;
            }

            int modBits = peBitness(image);
            if (modBits != programBits) {
                bitnessMismatch++;
                Msg.warn(this, "[HashResolver] bitness mismatch: " + dll + " is "
                        + modBits + "-bit, loaded program is " + programBits + "-bit");
            }

            try {
                long moduleHash = 0;
                if (moduleHashFunc != 0) {
                    moduleHash = callHash(program, monitor, mod, dll, 0, includeNul, holder);
                    record(table, moduleHash, dll, hashMask);
                    hashed++;
                }

                long seedVal = 0;
                if (seed.equals("FIXED")) {
                    seedVal = seedValue;
                } else if (seed.equals("MODULE_HASH")) {
                    seedVal = (moduleHashFunc != 0) ? moduleHash
                            : callHash(program, monitor, mod, dll, 0, includeNul, holder);
                }

                List<String> exports = parseExports(image);
                String prefix = stripDllSuffix(dll) + "!";
                int hashedHere = 0, skippedHere = 0;
                List<String> skippedExamples = new ArrayList<>();
                for (String name : exports) {
                    long h;
                    try {
                        h = callHash(program, monitor, api, name, seedVal, includeNul, holder);
                    } catch (Exception e) {
                        // A name the sample cannot hash can never be the preimage of one of its
                        // constants, so skipping it loses nothing. Conti copies each candidate into
                        // a 64-byte stack buffer unchecked, so names at or over that length fault.
                        skippedHere++;
                        if (skippedExamples.size() < MAX_SKIPPED_EXAMPLES)
                            skippedExamples.add(name + " (" + name.length()
                                    + " chars): " + e.getMessage());
                        continue;
                    }
                    record(table, h, prefix + name, hashMask);
                    hashed++;
                    hashedHere++;
                }

                // Every candidate faulting is an argument layout problem, not a long-name one.
                if (hashedHere == 0 && skippedHere > 0)
                    throw new Exception("every one of " + skippedHere
                            + " candidate names faulted in the sample's hash routine, so"
                            + " this is an argument layout problem rather than a property"
                            + " of the names. First failure: "
                            + (skippedExamples.isEmpty() ? "none recorded"
                                                         : skippedExamples.get(0)));

                skippedTotal += skippedHere;
                Map<String, Object> mr = row(dll, "ok", hex(moduleHash, hashMask),
                        hex(seedVal, hashMask), exports.size(), null);
                if (skippedHere > 0) {
                    mr.put("names_skipped", skippedHere);
                    mr.put("names_hashed", hashedHere);
                    mr.put("skipped_examples", skippedExamples);
                }
                if (corpusManifest) {
                    mr.put("bytes", image.length);
                    mr.put("sha256", sha256(image));
                    mr.put("pe_timestamp", peTimestamp(image));
                }
                moduleRows.add(mr);

            } catch (Exception e) {
                moduleRows.add(row(dll, "error", null, null, 0, e.getMessage()));
                errored++;
                Msg.warn(this, "[HashResolverService] " + dll + ": " + e.getMessage());
            }
        }

        holder.discard();

        long elapsed = System.currentTimeMillis() - start;

        // The same export name from several DLLs is aliasing, not a hash collision.
        // Only buckets holding genuinely different names threaten correctness.
        int aliased = 0, collisions = 0;
        List<String> collisionDetail = new ArrayList<>();
        for (Map.Entry<Long, List<String>> e : table.entrySet()) {
            if (e.getValue().size() < 2) continue;
            if (sameBaseName(e.getValue())) {
                aliased++;
            } else {
                collisions++;
                if (collisionDetail.size() < MAX_COLLISION_BUCKETS)
                    collisionDetail.add(describeBucket(e.getKey(), e.getValue(), hashMask));
            }
        }
        if (collisions > MAX_COLLISION_BUCKETS)
            collisionDetail.add("... " + (collisions - MAX_COLLISION_BUCKETS)
                    + " further colliding buckets not listed");

        // All candidates on one value means the name never reached the hash code.
        String degenerate = null;
        if (hashed > 1 && table.size() == 1) {
            degenerate = "all " + hashed + " candidates produced the same hash ("
                    + hex(table.keySet().iterator().next(), hashMask)
                    + "), so the candidate pointer "
                    + "did not reach the hash code. Check args and arg_regs against how the "
                    + "routine is actually called, and check that hash_func is the hash "
                    + "itself rather than a wrapper. If the hash loop is inlined with no "
                    + "entry point, set hash_func to the first address of the loop, hash_end "
                    + "to just past it, and place the pointer with arg_regs.";
            Msg.warn(this, "[HashResolver] DEGENERATE " + degenerate);
            audit(corpus, "[HashResolver] DEGENERATE " + degenerate);
        }

        if (degenerate != null) result.put("warning", degenerate);
        result.put("program", program.getName());
        result.put("modules", moduleRows);
        result.put("modules_resolved", modules.size() - missing - errored);
        result.put("modules_requested", modules.size());
        if (missing > 0) result.put("modules_missing", missing);
        if (errored > 0) result.put("modules_errored", errored);
        if (skippedTotal > 0) {
            result.put("names_skipped", skippedTotal);
            result.put("skip_note", skippedTotal + " candidate name(s) faulted in the"
                    + " sample's own hash routine and were skipped, so the sweep of the"
                    + " affected modules is partial. A name the sample cannot hash cannot"
                    + " be the preimage of one of its constants, but a target that comes"
                    + " back unresolved may sit past a skipped name. See names_skipped on"
                    + " each module row.");
        }
        result.put("program_bits", programBits);
        result.put("hash_bits", hashBits);
        result.put("bitness_mismatches", bitnessMismatch);
        result.put("names_hashed", hashed);
        result.put("distinct_hashes", table.size());
        result.put("cross_module_aliases", aliased);
        result.put("true_collisions", collisions);
        if (!collisionDetail.isEmpty()) result.put("collision_detail", collisionDetail);
        result.put("elapsed_ms", elapsed);
        result.put("ms_per_name", hashed == 0 ? 0.0
                : Math.round((double) elapsed / hashed * 100.0) / 100.0);

        if (targets.isEmpty()) {
            List<String> all = new ArrayList<>();
            for (Map.Entry<Long, List<String>> e : table.entrySet())
                all.add(hex(e.getKey(), hashMask) + "  " + String.join(" | ", e.getValue()));
            result.put("table", all);
            return Response.ok(result);
        }

        List<Map<String, Object>> lookups = new ArrayList<>();
        List<Map<String, Object>> annotations = new ArrayList<>();
        int correct = 0, wrong = 0, recovered = 0;
        int ambiguous = 0, unresolved = 0, unscored = 0;

        // A target the sample never reads is distinct from one it does.
        int usedTargets = 0, usedNamed = 0, unresolvedUsed = 0;

        for (Target t : targets) {
            List<String> names = table.get(t.hash & hashMask);

            // Unseeded schemes hash the same name in two DLLs identically, so narrow to
            // the resolving module when the sample's own resolver would have.
            if (names != null && names.size() > 1 && t.module != null) {
                List<String> f = new ArrayList<>();
                for (String n : names) if (n.startsWith(t.module + "!")) f.add(n);
                if (!f.isEmpty()) names = f;
            }

            if (t.used) usedTargets++;

            Map<String, Object> r = new LinkedHashMap<>();
            r.put("hash", hex(t.hash, hashMask));
            if (t.used) r.put("used", true);
            if (t.address != null) r.put("address", t.address);

            if (names == null) {
                unresolved++;
                if (t.used) unresolvedUsed++;
                r.put("verdict", "UNRESOLVED");
            } else if (names.size() > 1) {
                ambiguous++;
                r.put("verdict", "AMBIGUOUS");
                r.put("candidates", names.size() > MAX_NAMES_PER_BUCKET
                        ? names.subList(0, MAX_NAMES_PER_BUCKET) : names);
                if (names.size() > MAX_NAMES_PER_BUCKET)
                    r.put("candidate_count", names.size());
            } else if (t.unknown) {
                recovered++;
                r.put("verdict", "RECOVERED");
                r.put("name", names.get(0));
            } else if (t.expected == null) {
                unscored++;
                r.put("verdict", "RESOLVED");
                r.put("name", names.get(0));
            } else if (names.get(0).equalsIgnoreCase(t.expected)) {
                correct++;
                r.put("verdict", "OK");
                r.put("name", names.get(0));
            } else {
                wrong++;
                r.put("verdict", "WRONG");
                r.put("name", names.get(0));
                r.put("expected", t.expected);
            }
            Object name = r.get("name");
            Object verdict = r.get("verdict");
            boolean named = name != null && !"WRONG".equals(verdict);
            if (t.used && named) usedNamed++;
            if (named && t.address != null) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("address", t.address);
                a.put("comment", String.valueOf(name));
                annotations.add(a);
            }

            lookups.add(r);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("targets", targets.size());
        summary.put("correct", correct);
        summary.put("wrong", wrong);
        summary.put("recovered_no_ground_truth", recovered);
        summary.put("resolved_unscored", unscored);
        summary.put("ambiguous", ambiguous);
        summary.put("unresolved", unresolved);
        if (usedTargets > 0) {
            summary.put("used_targets", usedTargets);
            summary.put("used_named", usedNamed);
            summary.put("unresolved_used", unresolvedUsed);
            summary.put("unresolved_inert", unresolved - unresolvedUsed);
        }

        String resultLine = String.format(
                "[HashResolver] RESULT names_hashed=%d distinct=%d aliases=%d collisions=%d "
                + "program_bits=%d bitness_mismatches=%d modules_resolved=%d elapsed_ms=%d "
                + "| targets=%d correct=%d wrong=%d recovered=%d unscored=%d ambiguous=%d "
                + "unresolved=%d%s",
                hashed, table.size(), aliased, collisions,
                programBits, bitnessMismatch, modules.size() - missing, elapsed,
                targets.size(), correct, wrong, recovered, unscored, ambiguous, unresolved,
                (usedTargets > 0
                        ? String.format(" | used=%d used_named=%d unresolved_used=%d "
                                        + "unresolved_inert=%d",
                                usedTargets, usedNamed, unresolvedUsed,
                                unresolved - unresolvedUsed)
                        : "")
                + (annotations.isEmpty() ? "" : " annotations=" + annotations.size())
                + (degenerate == null ? "" : " DEGENERATE"));
        Msg.info(this, resultLine);
        audit(corpus, resultLine);

        for (String d : collisionDetail)
            audit(corpus, "[HashResolver] COLLISION " + d);
        for (Map<String, Object> l : lookups) {
            Object v = l.get("verdict");
            if ("AMBIGUOUS".equals(v))
                audit(corpus, "[HashResolver] AMBIGUOUS " + l.get("hash")
                        + " " + l.get("candidates"));
            else if ("UNRESOLVED".equals(v))
                audit(corpus, "[HashResolver] UNRESOLVED " + l.get("hash"));
            else if ("WRONG".equals(v))
                audit(corpus, "[HashResolver] WRONG " + l.get("hash")
                        + " got=" + l.get("name") + " expected=" + l.get("expected"));
        }

        if (!annotations.isEmpty()) result.put("annotations", annotations);
        result.put("lookups", lookups);
        result.put("summary", summary);
        return Response.ok(result);
    }

    // ── parameter parsing ─────────────────────────────────────────────────

    // An explicitly empty array means empty: substituting the default made
    // "nothing on the stack" inexpressible for a caller using only registers.
    private List<String> parseStringArray(String json, List<String> fallback) {
        if (json == null || json.isBlank()) return new ArrayList<>(fallback);
        try {
            Object parsed = JsonHelper.parseJson("{\"c\":" + json + "}").get("c");
            if (!(parsed instanceof List<?> list)) return new ArrayList<>(fallback);
            List<String> out = new ArrayList<>();
            for (Object item : list) out.add(String.valueOf(item));
            return out;
        } catch (Exception e) {
            return new ArrayList<>(fallback);
        }
    }

    private Map<String, String> parseStringMap(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return out;
        String body = json.trim();
        if (body.equals("{}") || body.equals("[]")) return out;
        try {
            Object parsed = JsonHelper.parseJson("{\"c\":" + body + "}").get("c");
            if (parsed instanceof Map<?, ?> m)
                for (Map.Entry<?, ?> e : m.entrySet())
                    out.put(String.valueOf(e.getKey()).trim().toUpperCase(),
                            String.valueOf(e.getValue()).trim());
        } catch (Exception e) {
            Msg.warn(this, "[HashResolver] cannot parse register map " + body
                    + ": " + e.getMessage());
        }
        return out;
    }

    private List<Target> parseTargets(List<String> specs) {
        List<Target> out = new ArrayList<>();
        for (String spec : specs) {
            if (spec == null) continue;
            String line = spec.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] tok = line.split("[\\s,]+");

            Target t = new Target();
            try {
                t.hash = parseLongValue(tok[0]);
            } catch (Exception e) {
                continue;
            }
            if (tok.length > 1) {
                String exp = tok[1];
                int bang = exp.indexOf('!');
                if (bang > 0) t.module = exp.substring(0, bang);
                if (exp.equals("?") || exp.endsWith("!?")) t.unknown = true;
                else t.expected = exp;
            }
            // A bare "used" after the hash marks a target whose output slot the sample
            // reads. Position-independent, so it composes with the module qualifier.
            for (int i = 1; i < tok.length; i++)
                if ("used".equalsIgnoreCase(tok[i])) t.used = true;
            out.add(t);
        }
        return out;
    }

    private static long parseLongValue(String s) {
        String v = s.trim();
        if (v.isEmpty()) return 0L;
        if (v.startsWith("0x") || v.startsWith("0X"))
            return Long.parseUnsignedLong(v.substring(2), 16);
        if (v.startsWith("-")) return Long.parseLong(v);
        return Long.parseLong(v);
    }

    // ── execution ─────────────────────────────────────────────────────────

    /** One emulator reused across candidate names.
     *
     *  A hash routine that builds a lookup table on first use otherwise pays that
     *  cost per candidate, since the guard flag resets with the emulator.
     *  Latrodectus builds a 256-entry CRC-32 table that way: ~18,000 emulated
     *  instructions against ~180 to hash a fifteen-character name.
     *
     *  Safe because every run rewrites SP, BP, PC and all argument registers, and
     *  writeString always terminates the candidate. A faulted run is discarded.
     */
    private static final class EmuHolder {
        private final Program program;
        private EmulatorHelper emu;

        EmuHolder(Program program) { this.program = program; }

        EmulatorHelper get() {
            if (emu == null) emu = new EmulatorHelper(program);
            return emu;
        }

        void discard() {
            if (emu == null) return;
            try {
                emu.dispose();
            } catch (Exception ignored) {
                // Disposal failing does not matter; the reference is dropped.
            }
            emu = null;
        }
    }

    private long callHash(Program program, TaskMonitor monitor, HashSpec spec,
                          String name, long seed, boolean includeNul,
                          EmuHolder holder) throws Exception {

        // Normalise first: by the sample's own code if given, else the declared fold.
        String s = applyCase(name, spec.fold);
        if (spec.charMap != null) s = mapChars(s, spec.charMap);
        else if (spec.normStringFunc != 0)
            s = normalizeString(program, monitor, spec.normStringFunc, s,
                    spec.enc, spec.resultReg, spec.bits);

        EmulatorHelper emu = holder.get();
        try {
            writeString(program, emu, SCRATCH, s, spec.enc);
            // Samples disagree about which a UTF-16 routine wants: NetWalker's module
            // hash takes a character count, Latrodectus's takes wcslen<<1.
            int units = s.length() + (includeNul ? 1 : 0);
            int bytes = units * ("UTF16".equals(spec.enc) ? 2 : 1);

            long[] stack = new long[spec.stackArgs.size()];
            for (int i = 0; i < stack.length; i++)
                stack[i] = resolveToken(spec.stackArgs.get(i), seed, units, bytes);

            Map<String, Long> regs = new LinkedHashMap<>();
            for (Map.Entry<String, String> e : spec.regArgs.entrySet())
                regs.put(e.getKey(), resolveToken(e.getValue(), seed, units, bytes));

            Map<Long, Long> frame = new LinkedHashMap<>();
            if (spec.frameArgs != null)
                for (Map.Entry<String, String> e : spec.frameArgs.entrySet())
                    frame.put(parseLongValue(e.getKey()),
                              resolveToken(e.getValue(), seed, units, bytes));

            return execute(program, monitor, emu, spec.entry, stack, regs, frame,
                    spec.stopAt, spec.resultReg, spec.bits, spec.mask,
                    "hashing \"" + name + "\"");
        } catch (Exception e) {
            // A faulted run may have left the emulator mid-instruction.
            holder.discard();
            throw e;
        }
    }

    private long resolveToken(String tok, long seed, int units, int bytes) {
        if ("NAME".equals(tok))      return SCRATCH;
        if ("SEED".equals(tok))      return seed;
        if ("LEN".equals(tok))       return units;
        // Separate token rather than redefining LEN, which NetWalker depends on.
        if ("LEN_BYTES".equals(tok)) return bytes;
        return parseLongValue(tok);
    }

    /**
     * Run a region of the sample's code and read the result register.
     *
     * <p>Stack arguments are laid out rightmost first and a sentinel return address
     * is pushed, so a function runs to its own return. Register arguments are
     * written after SP and BP are set, so a caller can override either.</p>
     *
     * <p>Slot width and register names come from the loaded program. A 64-bit
     * program also gets 32 bytes of shadow space, aligned so SP is congruent to 8
     * modulo 16 at entry; stack arguments then land at the fifth argument slot
     * onward, the first four arriving through {@code regArgs}.</p>
     *
     * <p>{@code stopAt} of zero runs to the sentinel; otherwise execution ends when
     * the PC reaches it, which allows an inlined hash loop to run alone.</p>
     */
    private long execute(Program program, TaskMonitor monitor, EmulatorHelper emu,
                         long entry, long[] stackArgs, Map<String, Long> regArgs,
                         Map<Long, Long> frameArgs, long stopAt, String resultReg,
                         int bits, long mask, String what)
            throws Exception {

        int slot   = bits / 8;
        int shadow = (bits == 64) ? 32 : 0;
        int n      = (stackArgs == null) ? 0 : stackArgs.length;

        // Size the whole frame first and place SP once, so alignment padding sits
        // above the arguments rather than where a callee looks for its fifth.
        long sp = STACK - ((long) n * slot + shadow + slot);
        if (bits == 64) sp -= (((sp - slot) % 16) + 16) % 16;

        emu.writeMemoryValue(addr(program, sp), slot, SENTINEL);

        // Rightmost first, so the leftmost argument sits nearest SP.
        long slotAddr = sp + slot + shadow;
        for (int i = 0; i < n; i++) {
            emu.writeMemoryValue(addr(program, slotAddr), slot, stackArgs[n - 1 - i]);
            slotAddr += slot;
        }

        emu.writeRegister(spReg(bits), sp);
        emu.writeRegister(bpReg(bits), STACK);

        // The frame the enclosing function would have had, for an inlined region.
        if (frameArgs != null)
            for (Map.Entry<Long, Long> e : frameArgs.entrySet())
                emu.writeMemoryValue(addr(program, STACK + e.getKey()), slot, e.getValue());
        if (regArgs != null)
            for (Map.Entry<String, Long> e : regArgs.entrySet()) {
                try {
                    emu.writeRegister(e.getKey(), e.getValue());
                } catch (Exception ex) {
                    throw new Exception("cannot write register " + e.getKey()
                            + ": " + ex.getMessage());
                }
            }
        emu.writeRegister(emu.getPCRegister(), entry);

        long halt = (stopAt != 0) ? stopAt : SENTINEL;
        int steps = 0;
        while (steps < MAX_STEPS) {
            if (emu.getExecutionAddress().getOffset() == halt) break;
            if (!emu.step(monitor)) {
                throw new Exception("fault at " + emu.getExecutionAddress()
                        + " " + what + ": " + emu.getLastError());
            }
            steps++;
        }
        if (steps >= MAX_STEPS)
            throw new Exception("step limit reached " + what + "; check the argument layout"
                    + (stopAt != 0 ? ", and that hash_end is on the path out of the loop"
                                   : ", and that hash_func is a function entry"));

        return emu.readRegister(resultReg).longValue() & mask;
    }

    // Execute a per-character normaliser across every byte value once.
    private byte[] charTable(Program program, TaskMonitor monitor, long func,
                             String resultReg, int bits) throws Exception {
        byte[] map = new byte[256];
        for (int c = 0; c < 256; c++) {
            EmulatorHelper emu = new EmulatorHelper(program);
            try {
                long r = execute(program, monitor, emu, func, new long[]{c}, null, null, 0,
                        resultReg, bits, -1L,
                        "normalising byte 0x" + Integer.toHexString(c));
                map[c] = (byte) (r & 0xFF);
            } finally {
                emu.dispose();
            }
        }
        return map;
    }

    private static String mapChars(String s, byte[] map) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++)
            b.append((char) (map[s.charAt(i) & 0xFF] & 0xFF));
        return b.toString();
    }

    // Call a whole-string normaliser and read the buffer back.
    private String normalizeString(Program program, TaskMonitor monitor, long func,
                                   String s, String enc, String resultReg, int bits)
            throws Exception {

        EmulatorHelper emu = new EmulatorHelper(program);
        try {
            writeString(program, emu, SCRATCH, s, enc);
            execute(program, monitor, emu, func, new long[]{SCRATCH}, null, null, 0,
                    resultReg, bits, -1L, "normalising \"" + s + "\"");

            boolean wide = "UTF16".equals(enc);
            int span = wide ? s.length() * 2 + 2 : s.length() + 1;
            byte[] out = emu.readMemory(addr(program, SCRATCH), span);

            StringBuilder b = new StringBuilder();
            int n = wide ? span / 2 : span;
            for (int i = 0; i < n; i++) {
                int ch = wide ? (out[i * 2] & 0xFF) | ((out[i * 2 + 1] & 0xFF) << 8)
                              : out[i] & 0xFF;
                if (ch == 0) break;
                b.append((char) ch);
            }
            return b.toString();
        } finally {
            emu.dispose();
        }
    }

    private static long optionalAddress(Program program, String spec) throws Exception {
        if (spec == null || spec.isBlank() || "0".equals(spec.trim())) return 0;
        Address a = ServiceUtils.parseAddress(program, spec);
        if (a == null) throw new Exception("Invalid address \"" + spec + "\": "
                + ServiceUtils.getLastParseError());
        return a.getOffset();
    }

    // The terminator is always written, for samples that use strlen.
    // include_nul says whether an explicit LEN argument counts it.
    private void writeString(Program program, EmulatorHelper e, long at,
                             String s, String enc) throws Exception {
        byte[] b;
        if ("UTF16".equals(enc)) {
            b = new byte[s.length() * 2 + 2];
            for (int i = 0; i < s.length(); i++) {
                b[i * 2]     = (byte) (s.charAt(i) & 0xFF);
                b[i * 2 + 1] = (byte) ((s.charAt(i) >> 8) & 0xFF);
            }
        } else {
            b = new byte[s.length() + 1];
            for (int i = 0; i < s.length(); i++) b[i] = (byte) s.charAt(i);
        }
        e.writeMemory(addr(program, at), b);
    }

    private Address addr(Program program, long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private void record(Map<Long, List<String>> table, long hash, String name, long mask) {
        table.computeIfAbsent(hash & mask, k -> new ArrayList<>()).add(name);
    }

    // True when every entry names the same export, differing only in module.
    // Case-insensitive: a sample that folds case cannot distinguish two spellings.
    private boolean sameBaseName(List<String> names) {
        String first = null;
        for (String n : names) {
            int bang = n.indexOf('!');
            String base = (bang < 0) ? n : n.substring(bang + 1);
            if (first == null) first = base;
            else if (!first.equalsIgnoreCase(base)) return false;
        }
        return true;
    }

    private String describeBucket(long hash, List<String> names, long mask) {
        if (names.size() <= MAX_NAMES_PER_BUCKET)
            return hex(hash, mask) + "  " + String.join(" | ", names);
        return hex(hash, mask) + "  " + names.size() + " names, first "
                + MAX_NAMES_PER_BUCKET + ": "
                + String.join(" | ", names.subList(0, MAX_NAMES_PER_BUCKET));
    }

    private static String sha256(byte[] b) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(b);
            StringBuilder sb = new StringBuilder(64);
            for (byte x : d) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) {
            return "unavailable: " + e.getMessage();
        }
    }

    // TimeDateStamp from the COFF header.
    private String peTimestamp(byte[] f) {
        try {
            long ts = rd32(f, rd32(f, 0x3C) + 8) & 0xFFFFFFFFL;
            return ts == 0 ? "0" : Instant.ofEpochSecond(ts).toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    private static String hex(long v, long mask) {
        return (mask == 0xFFFFFFFFL) ? String.format("0x%08X", v & mask)
                                     : String.format("0x%016X", v & mask);
    }

    private static String stripDllSuffix(String dll) {
        return dll.toLowerCase().endsWith(".dll")
                ? dll.substring(0, dll.length() - 4) : dll;
    }

    private Map<String, Object> row(String module, String status, String moduleHash,
                                    String seed, int exports, String error) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("module", module);
        r.put("status", status);
        if (moduleHash != null) r.put("module_hash", moduleHash);
        if (seed != null)       r.put("seed", seed);
        if ("ok".equals(status)) r.put("exports", exports);
        if (error != null)      r.put("error", error);
        return r;
    }

    // ── PE export parsing ─────────────────────────────────────────────────

    // A 32-bit sample is redirected to SysWOW64 even where its code names
    // System32, so a corpus from the wrong folder would be a silent error.
    private int peBitness(byte[] f) {
        int optHdr = rd32(f, 0x3C) + 4 + 20;
        return (rd16(f, optHdr) == 0x20B) ? 64 : 32;
    }

    private List<String> parseExports(byte[] f) {
        List<String> out = new ArrayList<>();
        int elfanew = rd32(f, 0x3C);
        int optHdr  = elfanew + 4 + 20;
        int magic   = rd16(f, optHdr);
        int dirOff  = (magic == 0x20B) ? optHdr + 0x70 : optHdr + 0x60;  // PE32+ / PE32
        int expRva  = rd32(f, dirOff);
        if (expRva == 0) return out;

        int nSec   = rd16(f, elfanew + 6);
        int optSz  = rd16(f, elfanew + 20);
        int secTab = elfanew + 4 + 20 + optSz;

        int expOff   = rvaToOff(f, expRva, secTab, nSec);
        int nNames   = rd32(f, expOff + 0x18);
        int namesOff = rvaToOff(f, rd32(f, expOff + 0x20), secTab, nSec);

        for (int i = 0; i < nNames; i++) {
            int nOff = rvaToOff(f, rd32(f, namesOff + i * 4), secTab, nSec);
            if (nOff < 0 || nOff >= f.length) continue;
            StringBuilder sb = new StringBuilder();
            for (int k = nOff; k < f.length && f[k] != 0; k++) sb.append((char) f[k]);
            if (sb.length() > 0) out.add(sb.toString());
        }
        return out;
    }

    // Appended to resolver_runs.log beside the corpus, since Ghidra's log level
    // is not controlled here. A write failure never aborts a run.
    private void audit(Path corpus, String line) {
        try {
            Path dir = corpus.getParent() != null ? corpus.getParent() : corpus;
            Path f = dir.resolve("resolver_runs.log");
            Files.write(f, (Instant.now() + "  " + line + System.lineSeparator())
                            .getBytes(StandardCharsets.UTF_8),
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception e) {
            Msg.warn(this, "[HashResolver] cannot write audit file: " + e.getMessage());
        }
    }

    // Three states, not two: a sample may fold up or down, and the two roles may
    // fold in opposite directions. Legacy boolean spellings still accepted.
    private static String applyCase(String name, String mode) {
        String m = mode == null ? "" : mode.trim().toLowerCase();
        if (m.equals("upper")) return name.toUpperCase();
        if (m.equals("lower") || m.equals("true")) return name.toLowerCase();
        return name;
    }

    private List<String> listCorpus(Path dir) {
        List<String> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, CORPUS_GLOB)) {
            for (Path p : ds) out.add(p.getFileName().toString());
        } catch (Exception e) {
            Msg.warn(this, "[HashResolverService] cannot list " + dir + ": " + e.getMessage());
        }
        return out;
    }

    private int rd16(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    private int rd32(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8)
             | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
    }

    // Translate a relative virtual address to a file offset via the section table.
    private int rvaToOff(byte[] f, int rva, int secTab, int nSec) {
        for (int i = 0; i < nSec; i++) {
            int sh  = secTab + i * 40;
            int va  = rd32(f, sh + 12);
            int vs  = rd32(f, sh + 8);
            int raw = rd32(f, sh + 16);
            int ptr = rd32(f, sh + 20);
            if (rva >= va && rva < va + Math.max(vs, raw)) return rva - va + ptr;
        }
        return rva;  // inside the headers
    }
}