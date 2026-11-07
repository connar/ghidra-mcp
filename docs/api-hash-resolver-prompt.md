# Frozen agent prompt for resolve_api_hashes

The prompt used for every end-to-end sample run. It must be pasted verbatim. The
harness under test is the resolver plus this prompt, so changing the wording changes
the experiment and invalidates comparison across samples.

One substitution is permitted and is a parameter rather than a prompt change: the
corpus path, `C:/dll_corpus/x86` for a 32-bit sample and `C:/dll_corpus/x64` for a
64-bit one. Record which was used alongside the run's results.

Any other change to the text is a prompt revision. Record it against the sample that
forced it, and re-run every earlier sample under the new wording before comparing
counts across samples.

The prompt deliberately forbids the agent from computing, recalling or guessing a
hash, and from using any code-execution tool. Only `resolve_api_hashes` may turn a
hash into a name. Without that constraint the run measures the model's recall of
published hash tables rather than the tool.

---

You are connected to GhidraMCP with a malware sample loaded. It resolves its Windows API calls by hashing API names and comparing against constants.

Rules for this run:

* Use only the GhidraMCP tools. Do not use a bash tool, a shell, a Python tool, run_script_inline, or any other code execution, even if one appears available.
* Resolve hashes only by calling `resolve_api_hashes`. Do not compute, guess or recall a hash value yourself, and do not identify the algorithm from memory.
* If `resolve_api_hashes` cannot resolve a constant, report it as unresolved. Do not work around it by any other means.

Tasks:

1. Locate every hash constant the sample compares against, with the address of each use site.
2. Determine what the resolver needs and resolve those constants to API names with `resolve_api_hashes`. The DLL corpus is at `C:/dll_corpus/x86`.
3. Write each resolved name back into the program as an EOL comment at the address where that hash is used.

The sample may hold what you need in a form you cannot read directly. In every such case the sample contains code that produces the readable form, so run that code with `emulate_function` rather than reconstructing what it does.

* A target constant may not appear in the listing at all, because a per-site function computes it at runtime from a masked global. Emulate that function and read its return value.
* A target constant may be stored transformed, for example XORed with a key. Find the transform in the code that consumes it, apply it, and pass the decoded values as targets.
* Module names may be held encrypted and fetched by index rather than walked from the module list. Emulate the decoder for every index the resolver call sites use and report the decoded name for each, so a module attribution is read from the binary rather than inferred.
* A name may be transformed before hashing. If that transform is reachable as a function, pass its address as `normalize_func` or `module_normalize_func` with the matching mode and leave the case-folding parameters at none. Only use `fold_case` when the transform is inlined at the call site with no function to call.
* If a target comes back AMBIGUOUS, the sample itself knows which module it meant, usually from an index or a handle at the call site. Establish that, then pass the target module-qualified as `module!?` so the resolver names it rather than you.

Never use emulation, or any other tool, to turn a hash into a name. Only `resolve_api_hashes` does that.

Then give me, in this order and nothing else:

A. The exact arguments you passed to `resolve_api_hashes`, verbatim as JSON, for every call you made.
B. The CSV in a code block, columns exactly: `address,hash,kind,module,resolved_name`. kind is MODULE or API. module is the DLL the hash resolved from. Lowercase hex, no 0x.
C. Counts: constants found, distinct constants, resolved, annotated, unresolved, cross_module_aliases, true_collisions, modules_resolved, bitness_mismatches.
D. Anything you could not do, could not resolve or were unsure about, and anything you needed that the tool did not offer.

Skip commentary. Do only what is asked.
