import { DataTypeManager } from "./DataTypeManager.1";
import { DomainObject } from "./DomainObject";

// https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/DataTypeManagerDomainObject.html
interface DataTypeManagerDomainObject extends DomainObject {
    getDataTypeManager(): DataTypeManager;
}