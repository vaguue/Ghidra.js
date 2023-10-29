const getOptions = () => ({
  'installDir': {
    type: 'string',
    default: process.env.GHIDRAJS_INSTALL_DIR,
    describe: 'Ghidra installation directory',
  },
  'buildOnly': {
    type: 'boolean',
    default: false,
    describe: 'Just build the script',
  },
  'output': {
    type: 'string',
    default: null,
    describe: 'Save the processed script to <path>',
  },
  'import': {
    type: 'string',
    default: null,
    describe: 'Import specified file or directory for analysis.'
  },
  'process': {
    type: 'string',
    default: null,
    describe: 'Processes an existing project file (instead of importing a new one).'
  },
  'preScript': {
    type: 'string',
    default: null,
    describe: 'Specifies a script to run before the analysis begins.'
  },
  'postScript': {
    type: 'string',
    default: null,
    describe: 'Specifies a script to run after the analysis has completed.'
  },
  'scriptPath': {
    type: 'string',
    default: process.env.GHIDRAJS_SCRIPT_PATH,
    describe: 'Adds additional script search paths.'
  },
  'propertiesPath': {
    type: 'string',
    default: process.env.GHIDRAJS_PROPERTIES_PATH,
    describe: 'Specifies the path for analysis properties files.'
  },
  'scriptlog': {
    type: 'string',
    default: process.env.GHIDRAJS_SCRIPTLOG,
    describe: 'Specifies the path for the script log file.'
  },
  'log': {
    type: 'string',
    default: process.env.GHIDRAJS_LOG,
    describe: 'Specifies the path for the tool log file.'
  },
  'overwrite': {
    type: 'boolean',
    default: process.env.GHIDRAJS_OVERWRITE,
    describe: 'Overwrite existing project file.'
  },
  'recursive': {
    type: 'boolean',
    default: process.env.GHIDRAJS_RECURSIVE,
    describe: 'Recursively processes directories.'
  },
  'readOnly': {
    type: 'boolean',
    default: process.env.GHIDRAJS_READ_ONLY,
    describe: 'Perform analysis in readonly mode.'
  },
  'deleteProject': {
    type: 'boolean',
    default: false,
    describe: 'Delete project after analysis.'
  },
  'noanalysis': {
    type: 'boolean',
    default: false,
    describe: 'Import or open file without analysis.'
  },
  'processor': {
    type: 'string',
    default: null,
    describe: 'Overrides the language ID.'
  },
  'cspec': {
    type: 'string',
    default: null,
    describe: 'Overrides the compiler spec ID.'
  },
  'analysisTimeoutPerFile': {
    type: 'number',
    default: null,
    describe: 'Sets the analysis timeout per file (in seconds).'
  },
  'keystore': {
    type: 'string',
    default: null,
    describe: 'Specifies the path for the keystore.'
  },
  'connect': {
    type: 'string',
    default: null,
    describe: 'Specifies the user ID for connecting to a shared project.'
  },
  'p': {
    type: 'boolean',
    default: null,
    describe: 'Prompt for password when connecting to shared project.'
  },
  'commit': {
    type: 'string',
    default: null,
    describe: 'Commit analyzed file with an optional comment.'
  },
  'okToDelete': {
    type: 'boolean',
    default: false,
    describe: 'Confirms that it\'s okay to delete a file or project.'
  },
  'maxcpu': {
    type: 'number',
    default: null,
    describe: 'Limit the maximum CPU cores the analysis can use.'
  },
  'loader': {
    type: 'string',
    default: null,
    describe: 'Specifies the desired loader by name.'
  },
});

const reservedOptions = ['_', '$0', 'projectLocation', 'projectName', 'installDir', 'buildOnly', 'output'];

module.exports = { getOptions, reservedOptions };
