const fs = require('fs/promises');
const path = require('path');
const { spawn } = require('child_process');

const yargs = require('yargs/yargs')
const { hideBin } = require('yargs/helpers')

const { build } = require('./webpack');
const { getOptions, reservedOptions } = require('./options');
const { getConfig, loadConfig, updateConfig, getConfigValue } = require('./config');

require('dotenv').config();

const isJs = str => /\.js$/.test(str);

async function lookupSource(fn, argv) {

}

async function processSource(fn, argv) {

}

async function processSources(argv) {
  const res = {};
  for (const [key, value] of Object.entries(argv)) {
    if (Array.isArray(value)) {
      res[key] = [...value];
    }
    else {
      res[key] = value;
    }
  }

  for (const [key, value] of Object.entries(res)) {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; ++i) {
        if (isJs(value[i])) {
          value[i] = await processSource(await lookupSource(value[i], argv), argv);
        }
      }
    }
    else {
      if (isJs(value)) {
        res[key] = await processSource(await lookupSource(value, argv), argv);
      }
    }
  }

  return res;
}

async function runCmd(argv) {
  argv = await processSources(argv);
  if (argv.buildOnly) { 
    if (argv.output) {
      return;
    }
    else {
      throw new Error('If you want to just build files to use from Ghidra - specify the `output` option');
    }
  }
  const { installDir, projectLocation, projectName } = argv;
  if (!installDir) {
    throw new Error('No Ghidra installation directory specified - exiting');
  }
  const analyzeHeadless = path.resolve(installDir, 'support', 'analyzeHeadless');
  const opts = [projectLocation];
  if (projectName) {
    opts.push(projectName);
  }
  for (const [key, value] of Object.entries(argv)) {
    if (reservedOptions.includes(key)) continue;
    if (key.includes('-')) continue;
    if (!value) continue;
    const flag = `-${key}`;
    if (value !== true) {
      if (Array.isArray(value)) {
        value.forEach(subValue => {
          opts.push(flag, subValue);
        });
      }
      else {
        opts.push(flag);
        opts.push(value);
      }
    }
  }
  const child = spawn(analyzeHeadless, opts);
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);
  child.on('close', (code) => {
    process.exit(code);
  });
}

async function configCmd(argv) {
  if (argv.value) {
    await updateConfig({ [argv.key]: argv.value });
    console.log(argv.value);
  }
  else {
    console.log(await getConfigValue(argv.key) || undefined);
  }
}

const rawArgv = hideBin(process.argv);

async function main() {
  const packageJson = JSON.parse(await fs.readFile(path.resolve(__dirname, 'package.json')).then(cnt => cnt.toString()));
  await loadConfig();
  const { argv } = yargs(rawArgv)
    .version(packageJson.version)
    .usage('usage: $0 <command>')
    .command('run <projectLocation> [projectName]', 'Run JavaScript in Ghidra', () => {}, runCmd)
    .command('config <key> [value]', 'Configure default arguments for runner (see help for available options and use them as key, e.g. config installDir /path/to/Ghidra)', 
      () => {}, configCmd)
    .options(getOptions())
    .check(argv => {
      if (argv.import && argv.process) {
        throw new Error('import and process cannot be both present in arguments');
      }
      return true;
    })
    .demandCommand()
    .strict()
    .help('h');
};

main().catch(console.error);
