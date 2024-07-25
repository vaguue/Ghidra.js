// https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/Address.html
export interface Address {
    add(displacement: number): Address;
    addNoWrap(displacement: number): Address;
    addNoWrap(displacement: BigInteger): Address;
    addWrap(displacement: number): Address;
    addWrapSpace(displacement: number): Address;
    equals(o: any): boolean;
    getAddress(addrString: string): Address;
    getAddressableWordOffset(): number;
    getAddressSpace(): AddressSpace;
    getNewAddress(byteOffset: number): Address;
    getNewAddress(offset: number, isAddressableWordOffset: boolean): Address;
    getNewTruncatedAddress(offset: number, isAddressableWordOffset: boolean): Address;
    getOffset(): number;
    getOffsetAsBigInteger(): BigInteger;
    getPhysicalAddress(): Address;
    getPointerSize(): number;
    getSize(): number;
    getUnsignedOffset(): number;
    hashCode(): number;
    hasSameAddressSpace(addr: Address): boolean;
    isConstantAddress(): boolean;
    isExternalAddress(): boolean;
    isHashAddress(): boolean;
    isLoadedMemoryAddress(): boolean;
    isMemoryAddress(): boolean;
    isNonLoadedMemoryAddress(): boolean;
    isRegisterAddress(): boolean;
    isStackAddress(): boolean;
    isSuccessor(addr: Address): boolean;
    isUniqueAddress(): boolean;
    isVariableAddress(): boolean;
    max(a: Address, b: Address): Address;
    min(a: Address, b: Address): Address;
    next(): Address;
    previous(): Address;
    subtract(displacement: number): Address;
    subtract(addr: Address): number;
    subtractNoWrap(displacement: number): Address;
    subtractWrap(displacement: number): Address;
    subtractWrapSpace(displacement: number): Address;
    toString(): string;
    toString(showAddressSpace: boolean): string;
    toString(showAddressSpace: boolean, pad: boolean): string;
    toString(showAddressSpace: boolean, minNumDigits: number): string;
    toString(prefix: string): string;
    //compareTo(addr: Address): number; // inherited from Comparable
}
