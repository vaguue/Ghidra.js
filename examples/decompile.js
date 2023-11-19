//Example of getting decompiler output of currenly opened function

const DecompInterface = JavaHelper.getClass('ghidra.app.decompiler.DecompInterface');

const monitor = currentAPI.getMonitor();

const decompiler = new DecompInterface();
decompiler.openProgram(currentProgram);

const getCurrentFunction = () => currentProgram.getFunctionManager().getFunctionContaining(currentAddress);
const decompile = func => {
  const decomp = decompiler.decompileFunction(func, 10000, monitor);
  if (decomp.isTimedOut() || !decomp.decompileCompleted()) {
    throw new Error('Error decompiling current function');
  }
  const src = decomp.getDecompiledFunction().getC();
  return src;
}

console.log(decompile(getCurrentFunction()));
