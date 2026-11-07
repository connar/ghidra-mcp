# API hash resolution by emulation

`resolve_api_hashes` resolves API-name hash constants to API names by executing the
sample's own hash code over names read from real DLL export tables.

Endpoint: `POST /resolve_api_hashes`. Tool group: `emulation`.
Implementation: `src/main/java/com/xebyte/core/HashResolverService.java`.

## The problem

Malware hides which Windows APIs it calls by replacing the import with a hash of the
export name (MITRE T1027.007, API hashing). At runtime the sample walks a module's
export table, hashes each name with its own routine, and compares against an embedded
constant. Nothing recognisable survives in the binary: no IAT entry, no name string,
only a 32-bit value. Static analysis sees `call eax`.

The usual answer is a precomputed table mapping hash to name for a set of known
algorithms. That works when the algorithm is one of the known ones and fails otherwise:

* The algorithm is undocumented, so no table exists for it.
* The algorithm is mutated per build, for example by changing a seed or a multiplier.
  One constant then means different names in two samples of the same family.
* A module hash seeds the API hash, so a name has no single hash; it has one per module.
* The name is normalised before hashing (case folding, a character map, a whole-string
  transform), so the table's input is not the name in the export table.

Reimplementing the algorithm by hand solves one sample at a time and introduces a second
source of error: the reimplementation can be wrong in ways that are hard to detect,
because a wrong hash usually resolves nothing rather than resolving incorrectly.

## The approach

The hash routine is already in the binary, correct by construction. This tool runs it.

Given the address of the hash code, a directory of DLLs, and the target constants, it
parses the export tables, emulates the sample's routine on each exported name with
Ghidra's `EmulatorHelper`, and matches the results against the targets. The output is
`constant -> module!name`.

No hash table, no reimplementation, and no candidate list: the candidates are the real
export names of real modules. An undocumented or per-build mutated algorithm needs no
change to the tool, because the algorithm is never modelled.

## How one run proceeds

1. Export names are read from each PE in `dll_dir`, narrowed by `scope`.
2. An emulator is set up on the loaded program: a stack, a scratch buffer for the
   candidate name, and arguments placed per `args`, `arg_regs` and `frame_args`.
3. For each candidate name: write the name into scratch in `encoding`, apply case
   folding or run `normalize_func` if given, execute from `hash_func` until the routine
   returns (or until `hash_end` for a loop inlined in a larger function with no entry
   point and no return), read `result_reg`, and mask to `hash_bits`.
4. Results are matched against `targets`.

Three details are worth stating because they are where per-family variation lives:

* **Emulator reuse.** One emulator serves the whole sweep. Some routines build state on
  first use, such as a 256-entry CRC table; rebuilding it per candidate dominated the
  run time before the emulator was reused.
* **Seeded schemes.** With `seed_mode = MODULE_HASH` the module name's hash seeds the
  API hash, so resolution is per module rather than against one flat table.
* **Ambiguity.** When a constant matches exports in more than one module, every candidate
  is reported rather than one being chosen. Ambiguity is set membership, not a failure,
  and the call site usually settles it.

## Parameters

31 parameters, all optional except `hash_func` and `dll_dir`.

| group | parameters |
|---|---|
| where the code is | `hash_func`, `hash_end`, `module_hash_func`, `module_hash_end` |
| how it receives the name | `args`, `module_args`, `arg_regs`, `module_arg_regs`, `frame_args`, `module_frame_args` |
| seeding | `seed_mode`, `seed_value` |
| name form | `encoding`, `module_encoding`, `fold_case`, `module_fold_case`, `normalize_func`, `normalize_mode`, `module_normalize_func`, `module_normalize_mode`, `include_nul` |
| result | `result_reg`, `module_result_reg`, `hash_bits` |
| corpus and targets | `dll_dir`, `scope`, `corpus_manifest`, `targets`, `names`, `addresses` |
| program selection | `program` |

`hash_bits` is separate from the program's bitness: a 64-bit sample can use a 32-bit
hash, and at least one family masks its result to 21 bits in the caller rather than in
the hash routine, which is what `hash_end` exists for.

Length is passed in whichever unit the routine expects. A routine taking a character
count and one taking a byte count are both common, and UTF-16 makes them differ by a
factor of two.

## Setup

**Build and install the extension.**

```
mvn package -DskipTests
```

Install the resulting extension zip in Ghidra (File > Install Extensions), restart, and
enable `GhidraMCPPlugin` in the Configure dialog. The plugin serves HTTP on
`127.0.0.1:8089` by default.

**Run the bridge.** The Python bridge exposes the plugin's endpoints as MCP tools:

```
python -m bridge_mcp_ghidra
```

It targets `http://127.0.0.1:8089` by default; override with `GHIDRA_MCP_URL`.

**Build the DLL corpus.** Candidate names come from real export tables, so the corpus
decides what can be resolved. Two directories, one per architecture:

```
C:\dll_corpus\x86\     32-bit system modules
C:\dll_corpus\x64\     64-bit system modules
```

The corpus must match the sample's bitness; a 32-bit sample against 64-bit modules
resolves nothing, and the tool reports the mismatch rather than returning empty.
`corpus_manifest` records the exact module set and file hashes for a run, which is what
makes a resolution reproducible: the same constants against a different corpus can
produce different ambiguity counts.

The timeout for this endpoint is set to 1800 s in `python/bridge_mcp_ghidra/config.py`,
since a full sweep over a large corpus is minutes rather than seconds.

## Reproducing a measurement

The agent-facing prompt is fixed and must be pasted verbatim; it is in
`docs/api-hash-resolver-prompt.md`. The harness under test is the resolver plus that
prompt, so changing the wording changes the experiment. One substitution is allowed and
is a parameter rather than a prompt change: the corpus path, `x86` or `x64`.

The prompt forbids the agent from computing, recalling or guessing a hash, and from
using any code-execution tool. Only `resolve_api_hashes` may turn a hash into a name.
This is what makes the measurement a measurement of the tool rather than of the model's
recall of published hash tables.

The prompt requires four sections back, in order:

* **A** — the verbatim JSON arguments of every `resolve_api_hashes` call
* **B** — a CSV, `address,hash,kind,module,resolved_name`
* **C** — counts: constants found, distinct, resolved, annotated, unresolved,
  cross-module aliases, true collisions, modules resolved, bitness mismatches
* **D** — anything unresolved, uncertain, or missing from the tool

Section A is the record of which tool calls were made, in a fixed format, stored with
the results. For a transport-level cross-check, run the bridge with
`GHIDRA_MCP_LOG_LEVEL=DEBUG`.

## Evaluation

The tool is scored against a ground truth built independently of it, so that a correct
answer is not defined by the thing being tested.

For each sample, the hash routine is read in Ghidra and reimplemented in Python, the use
sites and their constants are recorded in `targets.txt`, and a script parses the corpus
DLLs with `pefile`, hashes every export, and writes `gt_<sample>.csv`. That CSV is the
ground truth: constant, use site, role (API or MODULE), module, name, and the number of
modules a constant matched.

The tool's answer and the ground truth are then joined on the constant. Section B of the
prompt is already a CSV of constant to name, so the comparison is CSV to CSV with no
intermediate step. `compare.py` reports accuracy and completeness separately: `MATCH`,
`MISMATCH`, `UNRESOLVED` (the tool answered nothing), `MISSING` (the tool never saw the
constant) and `EXTRA` (the tool answered a constant not in the ground truth).

This makes the evaluation a differential test between two independent implementations of
the same algorithm — the sample's own code under emulation, and a hand-written Python
reimplementation — against the same corpus. Agreement is evidence; disagreement
localises the error to one of the two.

Example output for one sample:

```
constants   210
answered    208
match       210
mismatch    0
unresolved  0
missing     0
extra       0
ambiguous   0
accuracy    210/210 (100.0%)
```

## Where it is wired in

`CoreServices` builds the services both the GUI plugin and the headless server expose,
so one entry there registers the endpoint for both, and `tools/audit_server_scope.py`
picks it up with no further edit.

```java
HashResolverService hashResolver,          // record component
new HashResolverService(provider, ts),     // in build()
hashResolver, functionBundle, ...          // in all()
```

The endpoint itself is discovered from the `@McpTool` annotation by `AnnotationScanner`;
nothing registers it by hand.
