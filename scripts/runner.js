#!/usr/bin/env node
const os = require('os');
const path = require('path');
const fs = require('fs/promises');
const { spawn } = require('child_process');

const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const { exists } = require('./sys');
const { getGhidraDir } = require('./search');

const isWindows = process.platform === 'win32';

function fail(msg) {
  console.error(`[!] ${msg}`);
  process.exit(1);
};

async function findPackageRoot(start) {
  let dir = start;
  for (;;) {
    if (await exists(path.join(dir, 'package.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
};

// Resolve the target project from flags, the package.json "ghidra" field, and
// defaults. A project is either local ({ projectDir, projectName }) or a remote
// Ghidra Server repository ({ remote: true, url }).
async function resolveProject(argv) {
  const cwd = process.cwd();
  const pkgRoot = await findPackageRoot(cwd) || cwd;

  let pkg = {};
  try {
    pkg = JSON.parse(await fs.readFile(path.join(pkgRoot, 'package.json'), 'utf8'));
  } catch {}
  const cfg = pkg.ghidra || {};

  const projectRef = argv.project || cfg.project || '.';
  const connect = argv.connect || cfg.connect;
  const keystore = argv.keystore || cfg.keystore;
  const password = Boolean(argv.password);

  if (/^ghidra:\/\//i.test(projectRef)) {
    return { remote: true, url: projectRef.replace(/\/+$/, ''), connect, keystore, password };
  }

  const projectDir = path.resolve(pkgRoot, projectRef);
  const rawName = argv.name || cfg.name || pkg.name || 'ghidra';
  const projectName = String(rawName).replace(/^@/, '').replace(/[^A-Za-z0-9_.-]/g, '_');
  return { remote: false, projectDir, projectName, connect, keystore, password };
};

// analyzeHeadless leading args: a ghidra:// URL for remote, or
// "<location> <name>" for local, with an optional in-project folder appended.
function projectArgs(proj, folder) {
  const sub = folder ? '/' + String(folder).replace(/^\/+/, '') : '';
  return proj.remote ? [proj.url + sub] : [proj.projectDir, proj.projectName + sub];
};

function connectionArgs(proj) {
  const args = [];
  if (proj.connect) args.push('-connect', proj.connect);
  if (proj.password) args.push('-p');
  if (proj.keystore) args.push('-keystore', proj.keystore);
  return args;
};

// Interpret the `binary` argument for `run`. If it names a real file on disk,
// it is the imported source -> program sits at the project root under its
// basename. Otherwise it is an in-project reference that may include a folder
// (e.g. /malware/foo.so). An explicit --folder always wins.
async function resolveProgram(binaryArg, folderFlag) {
  if (folderFlag !== undefined) {
    return { folder: folderFlag, programName: path.basename(binaryArg) };
  }
  if (await exists(path.resolve(binaryArg))) {
    return { folder: '', programName: path.basename(binaryArg) };
  }
  const norm = binaryArg.replace(/^\/+/, '');
  const dir = path.dirname(norm);
  return { folder: dir === '.' ? '' : dir, programName: path.basename(norm) };
};

async function analyzeHeadlessPath() {
  const installDir = await getGhidraDir();
  return path.join(installDir, 'support', isWindows ? 'analyzeHeadless.bat' : 'analyzeHeadless');
};

function runHeadless(bin, args) {
  console.log(`[*] ${path.basename(bin)} ${args.join(' ')}`);
  return new Promise((resolve) => {
    const child = spawn(bin, args, { stdio: 'inherit' });
    child.on('error', (err) => fail(`failed to launch analyzeHeadless: ${err.message}`));
    child.on('close', (code) => resolve(code ?? 1));
  });
};

async function buildScript(scriptPath) {
  let esbuild;
  try {
    esbuild = require('esbuild');
  } catch {
    fail('esbuild is required to build scripts - run `npm install` in the ghidra.js package');
  }

  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'ghidrajs-'));
  const file = 'script.js';
  await esbuild.build({
    entryPoints: [scriptPath],
    outfile: path.join(dir, file),
    bundle: true,
    platform: 'node',
    format: 'iife',
    target: 'es2021',
    legalComments: 'none',
    logLevel: 'warning',
  });
  return { dir, file };
};

async function importCmd(argv) {
  const binaryPath = path.resolve(argv.binary);
  if (!await exists(binaryPath)) fail(`no such file: ${binaryPath}`);

  const proj = await resolveProject(argv);
  if (!proj.remote) await fs.mkdir(proj.projectDir, { recursive: true });

  const bin = await analyzeHeadlessPath();
  const args = [
    ...projectArgs(proj, argv.folder),
    '-import', binaryPath,
    ...connectionArgs(proj),
  ];
  if (argv.overwrite) args.push('-overwrite');
  if (argv.analysis === false) args.push('-noanalysis');
  if (argv.commit !== undefined) args.push('-commit', argv.commit === true ? '' : String(argv.commit));

  const where = proj.remote ? proj.url : `"${proj.projectName}" (${proj.projectDir})`;
  console.log(`[*] Importing ${path.basename(binaryPath)} into ${where}`);
  process.exit(await runHeadless(bin, args));
};

async function runCmd(argv) {
  const scriptPath = path.resolve(argv.script);
  if (!await exists(scriptPath)) fail(`no such script: ${scriptPath}`);

  const proj = await resolveProject(argv);
  const { folder, programName } = await resolveProgram(argv.binary, argv.folder);

  if (!proj.remote) {
    const hasProject =
      await exists(path.join(proj.projectDir, `${proj.projectName}.rep`)) ||
      await exists(path.join(proj.projectDir, `${proj.projectName}.gpr`));
    if (!hasProject) {
      fail(`no Ghidra project "${proj.projectName}" in ${proj.projectDir} - run \`ghidra.js import ${path.basename(argv.binary)}\` first`);
    }
  }

  const built = await buildScript(scriptPath);
  const bin = await analyzeHeadlessPath();
  const args = [
    ...projectArgs(proj, folder),
    '-process', programName,
    '-noanalysis',
    ...connectionArgs(proj),
    '-scriptPath', built.dir,
    '-postScript', built.file, ...(argv.scriptArgs || []),
  ];

  const where = proj.remote ? proj.url : `"${proj.projectName}"`;
  console.log(`[*] Running ${path.basename(scriptPath)} on ${programName} in ${where}`);
  const code = await runHeadless(bin, args);
  await fs.rm(built.dir, { recursive: true, force: true });
  process.exit(code);
};

const CONFIG_KEYS = ['project', 'name', 'connect', 'keystore'];

function detectIndent(text) {
  const m = text.match(/\n([ \t]+)"/);
  return m ? m[1] : '  ';
};

async function writePkg(pkgPath, raw, pkg) {
  const trailing = raw.endsWith('\n') ? '\n' : '';
  await fs.writeFile(pkgPath, JSON.stringify(pkg, null, detectIndent(raw)) + trailing);
};

async function configCmd(argv) {
  const pkgRoot = await findPackageRoot(process.cwd());
  if (!pkgRoot) fail('no package.json found - run `npm init` first');

  const pkgPath = path.join(pkgRoot, 'package.json');
  const raw = await fs.readFile(pkgPath, 'utf8');
  let pkg;
  try {
    pkg = JSON.parse(raw);
  } catch {
    fail(`could not parse ${pkgPath}`);
  }

  if (!CONFIG_KEYS.includes(argv.key)) {
    fail(`unknown config key "${argv.key}" (valid: ${CONFIG_KEYS.join(', ')})`);
  }

  const cfg = pkg.ghidra || {};

  if (argv.unset) {
    delete cfg[argv.key];
    if (Object.keys(cfg).length === 0) delete pkg.ghidra;
    else pkg.ghidra = cfg;
    await writePkg(pkgPath, raw, pkg);
    console.log(`[*] unset ghidra.${argv.key} in ${pkgPath}`);
    return;
  }

  // No value -> read the current setting.
  if (argv.value === undefined) {
    if (cfg[argv.key] !== undefined) console.log(cfg[argv.key]);
    return;
  }

  cfg[argv.key] = argv.value;
  pkg.ghidra = cfg;
  await writePkg(pkgPath, raw, pkg);
  console.log(`[*] ghidra.${argv.key} = ${argv.value}  (${pkgPath})`);
};

async function docsCmd(argv) {
  try {
    const { renderClass } = require('./docs');
    console.log(await renderClass(argv.class, { full: argv.full, method: argv.method }));
  } catch (err) {
    fail(err.message || String(err));
  }
};

const projectOptions = (y) => y
  .option('project', {
    type: 'string',
    describe: 'Project directory or ghidra:// URL (default: package.json\'s directory)',
  })
  .option('name', {
    type: 'string',
    describe: 'Project name for local projects (default: package.json "name")',
  })
  .option('connect', {
    type: 'string',
    describe: 'User ID for a shared/remote (ghidra://) project',
  })
  .option('password', {
    type: 'boolean',
    default: false,
    describe: 'Prompt for the shared-project password',
  })
  .option('keystore', {
    type: 'string',
    describe: 'PKI keystore path for shared-project authentication',
  });

yargs(hideBin(process.argv))
  .scriptName('ghidra.js')
  .usage('$0 <command>')
  .command(
    'import <binary>',
    'Import a binary into the project and analyze it',
    (y) => projectOptions(y)
      .positional('binary', { type: 'string', describe: 'Binary file to import' })
      .option('folder', { type: 'string', describe: 'In-project folder to import into' })
      .option('overwrite', { type: 'boolean', default: false, describe: 'Re-import, replacing an existing program' })
      .option('analysis', { type: 'boolean', default: true, describe: 'Run auto-analysis (use --no-analysis to skip)' })
      .option('commit', { describe: 'Commit to a shared project, with an optional message' }),
    importCmd,
  )
  .command(
    'run <script> <binary> [scriptArgs..]',
    'Run a script against an already-imported binary',
    (y) => projectOptions(y)
      .positional('script', { type: 'string', describe: 'JavaScript/TypeScript script to run' })
      .positional('binary', { type: 'string', describe: 'Imported program (name, in-project path, or source file)' })
      .positional('scriptArgs', { type: 'string', describe: 'Arguments passed to the script' })
      .option('folder', { type: 'string', describe: 'In-project folder holding the program' }),
    runCmd,
  )
  .command(
    'config <key> [value]',
    'Get or set a ghidra.js setting (project, name, connect, keystore) in the nearest package.json',
    (y) => y
      .positional('key', { type: 'string', describe: `Setting: ${CONFIG_KEYS.join(', ')}` })
      .positional('value', { type: 'string', describe: 'Value to set (omit to read the current value)' })
      .option('unset', { type: 'boolean', default: false, describe: 'Remove the setting' }),
    configCmd,
  )
  .command(
    'docs <class>',
    'Show Ghidra API docs for a class from the installation\'s bundled javadoc',
    (y) => y
      .positional('class', { type: 'string', describe: 'Class name or fully-qualified name' })
      .option('full', { type: 'boolean', default: false, describe: 'Include method descriptions' })
      .option('method', { type: 'string', describe: 'Show only this method\'s signature and description' }),
    docsCmd,
  )
  .demandCommand(1, 'Specify a command (import, run, config, or docs)')
  .strict()
  .help()
  .fail((msg, err) => {
    if (err) fail(err.message || String(err));
    fail(msg);
  })
  .parse();
