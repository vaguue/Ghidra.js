<p align='center'>
  <img src='assets/logo.png' width='180' alt='Hacker spider'>
</p>


# Ghidra JavaScript Integration [![GitHub license](https://img.shields.io/github/license/vaguue/Ghidra.js?style=flat)](https://github.com/vaguue/Ghidra.js/blob/main/LICENSE) [![npm](https://img.shields.io/npm/v/ghidra.js)](https://www.npmjs.com/package/ghidra.js)

## Overview
This project integrates JavaScript into the Ghidra reverse-engineering framework using the [Javet](https://github.com/caoccao/Javet) library. For more details about the choice of the library, see the [Library Choice](#library-choice) section.

## System Requirements
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) framework installed
- Supported platforms: Windows (x86_64), Linux (x86_64), MacOS (x86_64 or arm64)
- (Optional) npm installed

## Getting Started
You can download the .zip archive for your platform from the Releases section. Then open your Ghidra installation, go to `File -> Install Extensions`, click the `+` symbol, and select the downloaded archive. The extension will be active in the next Ghidra launch. Alternatively, you can install via npm, ensuring Ghidra's installation folder is in your PATH (the folder containing the `ghidraRun` script). For example:

```bash
export PATH="$PATH:/path/to/your/Ghidra"
npm install -g ghidra.js
```

## Command-Line Interface
Installing the package also gives you a `ghidra.js` CLI that wraps Ghidra's `analyzeHeadless`, so you can import binaries and run scripts on them straight from the terminal — no GUI needed. Your Ghidra installation is located automatically (following the `ghidraRun` launcher, common install paths, or `GHIDRA_INSTALL_DIR`).

Run it with `npx ghidra.js <command>`, or install globally (`npm install -g ghidra.js`) and call `ghidra.js` directly.

### Quickstart
```bash
# 1. Import a binary into a Ghidra project (runs auto-analysis once)
npx ghidra.js import ./target.bin

# 2. Run a script against the analyzed program (JavaScript or TypeScript)
npx ghidra.js run analyze.ts target.bin
```
The model is **import once, run many**: `import` creates a Ghidra project in the current directory and analyzes the binary; `run` reuses that already-analyzed program, so iterating on a script is fast. Scripts get the same globals as inside Ghidra (`currentProgram`, `JavaHelper`, Node built-ins, …) — see [Example Code](#example-code). Changes a script makes are saved back into the project.

### Commands
```bash
# Import a binary (add --no-analysis to skip analysis, --overwrite to re-import)
ghidra.js import <binary> [--no-analysis] [--overwrite] [--folder <dir>]

# Run a script; pass arguments to the script after `--`
ghidra.js run <script.js|.ts> <binary> [-- <scriptArgs...>]

# Read/write project settings in the nearest package.json (git-config style)
ghidra.js config <key> [value] [--unset]      # keys: project, name, connect, keystore
```
The `<binary>` for `run` can be the source file path, the program's name in the project, or an in-project path like `/malware/foo.so` (or use `--folder`).

### Project configuration
With no configuration, `import`/`run` use a project named after the nearest `package.json` (or `ghidra`) located in that package's directory — so the commands just work from any project. To pin a specific project directory or name, use `config` or add a `"ghidra"` field to `package.json`:
```jsonc
// package.json
"ghidra": {
  "project": "./re",       // directory holding the .gpr, or a ghidra:// URL
  "name": "analysis"       // project name
}
```

### TypeScript
`run` builds scripts with [esbuild](https://esbuild.github.io/) before handing them to Ghidra, so `.ts` files work out of the box — no manual compilation. Install the typings for editor support:
```bash
npm install --save-dev @types/ghidra.js
```

### Remote / shared projects
To work against a [Ghidra Server](https://ghidra.re/) repository, point `project` at a `ghidra://` URL and supply credentials:
```bash
npx ghidra.js config project ghidra://server:13100/my-repo
npx ghidra.js config connect alice
npx ghidra.js import ./target.bin --commit "initial import"
npx ghidra.js run analyze.ts target.bin
```
Connection flags (`--connect <user>`, `--password`, `--keystore <path>`) are also available per-command.

## Writing scripts in TypeScript inside Ghidra
When running scripts through Ghidra's own Script Manager (not the CLI), there is no build step, so TypeScript must be compiled to JavaScript first. The [`@types/ghidra.js`](#typescript) typings work the same in either case.

## Example Code
To start using the extension, refer to the following code example. More information can be found in the [Ghidra API documentation](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html). More examples can be found in the [ghidra_scripts](https://github.com/vaguue/Ghidra.js/tree/main/ghidra_scripts) folder.

```javascript
//you can use Node.js modules 
const fs = require('fs');
// JavaHelper.getClass is a helper method to import Java classes
const EmulatorHelper = JavaHelper.getClass('ghidra.app.emulator.EmulatorHelper');

const domainFile = currentProgram.getDomainFile();

console.log('Current arch:', process.arch); //Node globals are also available
console.log('Program Name:', currentProgram.getName());
console.log('Program Path:', domainFile.getPathname());
console.log('File Format:', currentProgram.getExecutableFormat());
console.log('Language:', currentProgram.getLanguageID().getIdAsString());
console.log('Compiler Spec:', currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());

// To make changes, use Ghidra's transaction API
// This is to give users more flexibility without automatic setup
const id = currentProgram.startTransaction('Hello world comment');

const functionManager = currentProgram.getFunctionManager();

const symbols = currentProgram.getSymbolTable().getGlobalSymbols('main')
if (symbols) {
  const [mainSymbol] = symbols;
  const main = functionManager.getFunctionAt(mainSymbol.getAddress());
  main.setComment('Hello world from JavaScript');
}
else {
  console.log('[!] Main function not found');
}

currentProgram.endTransaction(id, true);
```

## Running Scripts

### Within Ghidra
To run scripts inside the Ghidra environment, follow these steps:
1. Open Ghidra and load your project.
2. Navigate to the "Script Manager" by clicking on the "Window" menu and selecting "Script Manager".
3. In the Script Manager, locate your JavaScript file. You can import your script by clicking the "Manage Script Directories" icon and adding the directory where your script is located.
4. Double-click on the script to run it, or select the script and click the "Run" button.

### Using analyzeHeadless
You can also run scripts in a headless (non-GUI) mode using the `analyzeHeadless` command. This is particularly useful for automated analysis or batch processing. Here’s an example command:

```bash
/path/to/Ghidra/support/analyzeHeadless /path/to/projectDir -process yourExecutable -scriptPath /path/to/scripts -postScript YourScript.js
```

Replace /path/to/Ghidra with the installation directory of Ghidra, /path/to/projectDir with the path to your project directory, yourExecutable with file you want to analyze, /path/to/scripts with the directory containing your script, and YourScript.js with the name of your JavaScript file.

## Library Choice
I considered three options for the extension backend: Rhino, GraalJS, and Javet. All options were suitable to some extent, but Javet was the most fitting due to the following reasons:
- **Performance:** Javet uses the V8 engine, which can be hundreds of times faster than alternatives in my benchmarks.
- **ESM Standard:** Javet supports the latest JavaScript standards, which is a significant advantage over Rhino.
- **No JVM Alteration Needed:** This requirement significantly complicates the full use of GraalJS.

These arguments are not criticisms of the alternatives but rather my reasoning for choosing the backend for the extension. The repository still contains code for working through Rhino and GraalJS, just in case.

## Questions or Suggestions
Feel free to open any issue in the Issues section of this repository. Currently, there are no restrictions on the format.
