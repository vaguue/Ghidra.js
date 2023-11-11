# Ghidra JavaScript Integration

## Overview
This project integrates JavaScript into the Ghidra reverse-engineering framework using the [Javet](https://github.com/caoccao/Javet) library. For more details about the choice of the library, see the [Library Choice](#library-choice) section.

## System Requirements
- Ghidra framework installed
- Supported platforms: Windows (x86_64), Linux (x86_64), MacOS (x86_64 or arm64)
- (Optional) npm installed

## Getting Started
You can download the .zip archive for your platform from the Releases section. Then open your Ghidra installation, go to `File -> Install Extensions`, click the `+` symbol, and select the downloaded archive. The extension will be active in the next Ghidra launch. Alternatively, you can install via npm, ensuring Ghidra's installation folder is in your PATH (the folder containing the `ghidraRun` script). For example:

```bash
export PATH="$PATH:/path/to/your/Ghidra"
npm install -g ghidra.js
```

## Example Code
To start using the extension, refer to the following code example. More information can be found in the [Ghidra API documentation](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html).

```javascript
// JavaHelper.getClass is a helper method to import Java classes
const EmulatorHelper = JavaHelper.getClass('ghidra.app.emulator.EmulatorHelper');

const domainFile = currentProgram.getDomainFile();

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

## Library Choice
I considered three options for the extension backend: Rhino, GraalJS, and Javet. All options were suitable to some extent, but Javet was the most fitting due to the following reasons:
- **Performance:** Javet uses the V8 engine, which can be hundreds of times faster than alternatives in my benchmarks.
- **ESM Standard:** Javet supports the latest JavaScript standards, which is a significant advantage over Rhino.
- **No JVM Alteration Needed:** This requirement significantly complicates the full use of GraalJS.

These arguments are not criticisms of the alternatives but rather my reasoning for choosing the backend for the extension. The repository still contains code for working through Rhino and GraalJS, just in case.

## Questions or Suggestions
Feel free to open any issue in the Issues section of this repository. Currently, there are no restrictions on the format.
