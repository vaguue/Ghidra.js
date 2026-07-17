---
name: ghidra-scripting
description: Write and run JavaScript/TypeScript scripts for Ghidra with the Ghidra.js extension and its `ghidra.js` CLI. Use when analyzing a binary, decompiling functions, renaming/commenting, or automating Ghidra headlessly.
---

# Ghidra.js scripting

[Ghidra.js](https://github.com/vaguue/Ghidra.js) runs JavaScript/TypeScript inside
[Ghidra](https://ghidra.re/) via the Javet (Node.js/V8) engine. Scripts drive Ghidra's
Java API directly, either from Ghidra's Script Manager or headlessly through the
`ghidra.js` CLI.

## Running a script

Prefer the CLI. The model is **import once, run many**:

```bash
# Import a binary into a project (auto-analyzes once). Creates the project in cwd.
npx ghidra.js import ./target.bin

# Run a script against the already-analyzed program (JS or TS). Fast to iterate.
npx ghidra.js run analyze.ts target.bin

# Pass arguments to the script after `--` (available as the ARGV global)
npx ghidra.js run analyze.ts target.bin -- 0x1000 verbose
```

`import` runs auto-analysis; `run` reuses that analysis (`-noanalysis`) so re-running a
script is cheap. Changes a script makes are saved back into the project. To run inside the
GUI instead, add the script's folder in the Script Manager and double-click it.

## The scripting environment

These globals are injected (same as Ghidra's Java `GhidraScript` state):

- `currentProgram` — the `Program` being analyzed. The main entry point to the API.
- `currentAPI` / `script` — the `GhidraScript` instance; use `currentAPI.getMonitor()`
  for a `TaskMonitor`.
- `currentAddress`, `currentLocation`, `currentSelection` — cursor state (may be null in
  headless runs).
- `ARGV` — array of arguments passed to the script.
- `JavaHelper.getClass('fully.qualified.ClassName')` — import any Ghidra/Java class.
- `console.log`, `require(...)`, and Node.js built-ins (`fs`, `assert`, …) all work.

Import Java classes by name and use them like JS classes:

```javascript
const DecompInterface = JavaHelper.getClass('ghidra.app.decompiler.DecompInterface');
const decompiler = new DecompInterface();
decompiler.openProgram(currentProgram);
```

## Making changes: transactions

Reads need no ceremony, but **any modification** (renames, comments, data types, patches)
must be wrapped in a Ghidra transaction, or it will throw:

```javascript
const id = currentProgram.startTransaction('Rename main');
try {
  const fm = currentProgram.getFunctionManager();
  const [sym] = currentProgram.getSymbolTable().getGlobalSymbols('main');
  fm.getFunctionAt(sym.getAddress()).setComment('entry point');
} finally {
  currentProgram.endTransaction(id, true); // true = commit
}
```

## Common recipes

```javascript
// Iterate functions
const fm = currentProgram.getFunctionManager();
const it = fm.getFunctions(true); // true = forward
while (it.hasNext()) {
  const f = it.next();
  console.log(f.getName(), String(f.getEntryPoint()));
}

// Decompile the function at an address
const DecompInterface = JavaHelper.getClass('ghidra.app.decompiler.DecompInterface');
const decompiler = new DecompInterface();
decompiler.openProgram(currentProgram);
const func = fm.getFunctionContaining(currentAddress);
const res = decompiler.decompileFunction(func, 60, currentAPI.getMonitor());
if (res.decompileCompleted()) console.log(res.getDecompiledFunction().getC());
```

## Runtime constraints

The `run` CLI bundles scripts with esbuild to an IIFE for the Javet engine, so:

- **No top-level ESM `import`/`export`.** Use `require(...)` for Node modules; the Ghidra
  API comes from the injected globals above, not from imports.
- **No top-level `await`.** Wrap async work in an `(async () => { ... })()` IIFE.
- TypeScript works out of the box (esbuild strips types). Install editor typings with
  `npm install --save-dev @types/ghidra.js`.

## API reference

Do not guess Ghidra API signatures — your knowledge may be approximate for niche or newer
classes. Look them up from the installed Ghidra's own javadoc, which matches the exact
version in use:

```bash
npx ghidra.js docs DecompInterface              # class summary + method signatures
npx ghidra.js docs FunctionManager --method getFunctionAt   # one method's detail
npx ghidra.js docs ghidra.program.model.listing.Function --full
```

Pass a simple class name; if it is ambiguous the command lists fully-qualified candidates
to choose from. Good starting points: `FlatProgramAPI`, `Program`, `FunctionManager`,
`DecompInterface`. The full API is also online at
<https://ghidra.re/ghidra_docs/api/>.
