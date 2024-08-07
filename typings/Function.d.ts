// https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Function.html

export interface Function {
  addLocalVariable(var: Variable, source: SourceType): Variable;
  addParameter(var: Variable, source: SourceType): Parameter;
  addTag(name: string): boolean;
  getAllVariables(): Variable[];
  getAutoParameterCount(): number;
  getCalledFunctions(monitor: TaskMonitor): java.util.Set<Function>;
  getCallFixup(): string;
  getCallingConvention(): PrototypeModel;
  getCallingConventionName(): string;
  getCallingFunctions(monitor: TaskMonitor): java.util.Set<Function>;
  getComment(): string;
  getCommentAsArray(): java.lang.String[];
  getDefaultCallingConventionName(): string;
  getEntryPoint(): Address;
  getExternalLocation(): ExternalLocation;
  getFunctionThunkAddresses(): Address[];
  getLocalVariables(): Variable[];
  getLocalVariables(filter: VariableFilter): Variable[];
  getName(): string;
  getParameter(ordinal: number): Parameter;
  getParameterCount(): number;
  getParameters(): Parameter[];
  getParameters(filter: VariableFilter): Parameter[];
  getProgram(): Program;
  getPrototypeString(formalSignature: boolean, includeCallingConvention: boolean): string;
  getRepeatableComment(): string;
  getRepeatableCommentAsArray(): java.lang.String[];
  getReturn(): Parameter;
  getReturnType(): DataType;
  getSignature(): FunctionSignature;
  getSignature(formalSignature: boolean): FunctionSignature;
  getSignatureSource(): SourceType;
  getStackFrame(): StackFrame;
  getStackPurgeSize(): number;
  //getTags(): java.util.Set<FunctionTag>;
  getThunkedFunction(recursive: boolean): Function;
  getVariables(filter: VariableFilter): Variable[];
  hasCustomVariableStorage(): boolean;
  hasNoReturn(): boolean;
  hasVarArgs(): boolean;
  insertParameter(ordinal: number, var: Variable, source: SourceType): Parameter;
  isDeleted(): boolean;
  isExternal(): boolean;
  isInline(): boolean;
  isStackPurgeSizeValid(): boolean;
  isThunk(): boolean;
  moveParameter(fromOrdinal: number, toOrdinal: number): Parameter;
  promoteLocalUserLabelsToGlobal(): void;
  removeParameter(ordinal: number): void;
  removeTag(name: string): void;
  removeVariable(var: Variable): void;
  replaceParameters(updateType: Function.FunctionUpdateType, force: boolean, source: SourceType, params: Variable...): void;
  replaceParameters(params: java.util.List<?extendsVariable>, updateType: Function.FunctionUpdateType, force: boolean, source: SourceType): void;
  setBody(newBody: AddressSetView): void;
  setCallFixup(name: string): void;
  setCallingConvention(name: string): void;
  setComment(comment: string): void;
  setCustomVariableStorage(hasCustomVariableStorage: boolean): void;
  setInline(isInline: boolean): void;
  setName(name: string, source: SourceType): void;
  setNoReturn(hasNoReturn: boolean): void;
  setRepeatableComment(comment: string): void;
  setReturn(type: DataType, storage: VariableStorage, source: SourceType): void;
  setReturnType(type: DataType, source: SourceType): void;
  setSignatureSource(signatureSource: SourceType): void;
  setStackPurgeSize(purgeSize: number): void;
  setThunkedFunction(thunkedFunction: Function): void;
  setVarArgs(hasVarArgs: boolean): void;
  updateFunction(callingConvention: string, returnValue: Variable, updateType: Function.FunctionUpdateType, force: boolean, source: SourceType, newParams: Variable...): void;
  updateFunction(callingConvention: string, returnVar: Variable, newParams: java.util.List<?extendsVariable>, updateType: Function.FunctionUpdateType, force: boolean, source: SourceType): void;
}
