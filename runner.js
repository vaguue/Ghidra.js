const path = require('path');
const { spawn } = require('child_process');
const yargs = require('yargs/yargs')
const { hideBin } = require('yargs/helpers')
require('dotenv').config();

/*
analyzeHeadless <project_location> <project_name>[/<folder_path>] | ghidra://<server>[:<port>]/<repository_name>[/<folder_path>]
    [[-import [<directory>|<file>]+] | [-process [<project_file>]]]
    [-preScript <ScriptName> [<arg>]*]
    [-postScript <ScriptName> [<arg>]*]
    [-scriptPath "<path1>[;<path2>...]"]
    [-propertiesPath "<path1>[;<path2>...]"]
    [-scriptlog <path to script log file>]
    [-log <path to log file>]
    [-overwrite]
    [-recursive]
    [-readOnly]
    [-deleteProject]
    [-noanalysis]
    [-processor <languageID>]
    [-cspec <compilerSpecID>]
    [-analysisTimeoutPerFile <timeout in seconds>]
    [-keystore <KeystorePath>]
    [-connect [<userID>]]
    [-p]
    [-commit ["<comment>"]]
    [-okToDelete]
    [-max-cpu <max cpu cores to use>]
    [-loader <desired loader name>]

JS:
  -installDir
  -buildOnly
  -output
*/

const options = {
  installDir: {
    type: 'string',
    default: process.env.GHIDRA_INSTALL_DIR,
    describe: 'Ghidra installation directory',
  },
};

const { argv } = yargs(hideBin(process.argv))
  .version('1.0.0')
  .command('$0 [source]', 'Run JavaScript in Ghidra', () => {})
  .options(options)
  .check(argv => {
    return true;
  })
  .strict()
  .help('h');

async function main() {

}

main().catch(console.error);
