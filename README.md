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

## TypeScript usage
If you want to write scripts for Ghidra in TypeScript, for now you have to compile them to JavaScript by yourself, and you can install the typings with this command
```bash
npm install --save @types/ghidra.js
```

## Example Code
To start using the extension, refer to the following code example. More information can be found in the [Ghidra API documentation](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html). More examples can be found in the [examples](https://github.com/vaguue/Ghidra.js/tree/main/examples) folder.

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
