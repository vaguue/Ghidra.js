//JavaHelper.getClass is a helper method to import Java classes
const EmulatorHelper = JavaHelper.getClass('ghidra.app.emulator.EmulatorHelper');

const domainFile = currentProgram.getDomainFile();

console.log('Program Name:', currentProgram.getName());
console.log('Program Path:', domainFile.getPathname());
console.log('File Format:', currentProgram.getExecutableFormat());
console.log('Language:', currentProgram.getLanguageID().getIdAsString());
console.log('Compiler Spec:', currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());

//if you want to make changes, you should use Ghidra's transaction API
//The reason for this is I want to give more flexibility to users without setting this up automatically
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
