const path = require('path');
const fs = require('fs/promises');
const { XMLParser, XMLBuilder, XMLValidator} = require('fast-xml-parser');

const CodeUnit = JavaHelper.getClass('ghidra.program.model.listing.CodeUnit');
const SourceType = JavaHelper.getClass('ghidra.program.model.symbol.SourceType');
const monitor = currentAPI.getMonitor();

const options = {
  ignoreAttributes: false,
  attributeNamePrefix : "@"
};

async function getXmlData() {
  const parser = new XMLParser(options);

  const [publicObj, stringsObj] = await Promise.all(['public.xml', 'strings.xml'].map(e => 
    fs.readFile(path.resolve(__dirname, 'artefacts', e))
    .then(content => parser.parse(content))
  ));

  const publicMap = publicObj.resources.public.reduce((res, e) => res.set(e['@name'], parseInt(e['@id'], 16)), new Map());
  const stringsMap = stringsObj.resources.string.reduce((res, e) => res.set(publicMap.get(e['@name']), e['#text']), new Map());

  const search = id => {
    return stringsMap.get(id);
  };

  return { search };
}

function forEachInstruction(func, cb) {
  const listing = currentProgram.getListing();
  const addrs = func.getBody();
  const end = addrs.getMaxAddress();
  let instr = listing.getInstructionAt(addrs.getMinAddress());
  while (end.subtract(instr.getAddress()) > 0) {
    cb(instr);
    instr = instr.getNext();
  }
}

function resolveStrings(searchKey) {
  const listing = currentProgram.getListing();
  const equateTable = currentProgram.getEquateTable();

  forEachInstruction(currentProgram.getFunctionManager().getFunctionContaining(currentAddress), (instr) => {
    const mnemonic = instr.getMnemonicString();
    if (mnemonic === 'const') {
      const key = parseInt(instr.getDefaultOperandRepresentation(1), 16);
      const str = searchKey(key);
      if (str) {
        console.log('Found string reference:', str);
        const equate = equateTable.getEquate(str) || equateTable.createEquate(str, key);
        equate.addReference(instr.getAddress(), 1);
      }
    }
  });
}

async function main() {
  const { search } = await getXmlData();
  resolveStrings(search)
}

const id = currentProgram.startTransaction('Annotate Android strings');
main().catch(err => console.error(err.toString()));
currentProgram.endTransaction(id, true);
