const os = require('os');
const path = require('path');
const fs = require('fs/promises');

const { exists } = require('./sys');

const isWindows = process.platform === 'win32';
const launcherNames = isWindows ? ['ghidraRun.bat'] : ['ghidraRun'];

async function isGhidraDir(dir) {
  return (
    await exists(path.resolve(dir, 'ghidraRun')) &&
    await exists(path.resolve(dir, 'Ghidra', 'Extensions'))
  );
};

async function getGhidraDirLegacy() {
  const fromEnv = process.env.GHIDRA_INSTALL_DIR;
  if (fromEnv && await isGhidraDir(fromEnv)) {
    return path.resolve(fromEnv);
  }

  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (dir && await isGhidraDir(dir)) {
      return path.resolve(dir);
    }
  }

  return null;
};

async function isGhidraRoot(dir) {
  return exists(path.join(dir, 'Ghidra', 'application.properties'));
};

async function findGhidraRoot(start, maxDepth = 4) {
  const queue = [{ dir: path.resolve(start), depth: 0 }];
  const seen = new Set();
  let visited = 0;

  while (queue.length) {
    const { dir, depth } = queue.shift();
    if (visited++ > 5000) break;

    let real;
    try {
      real = await fs.realpath(dir);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);

    if (await isGhidraRoot(real)) return real;
    if (depth >= maxDepth) continue;

    let entries;
    try {
      entries = await fs.readdir(real, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
      if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
      queue.push({ dir: path.join(real, entry.name), depth: depth + 1 });
    }
  }

  return null;
};

async function launchersFromPath() {
  const result = [];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const name of launcherNames) {
      const fn = path.join(dir, name);
      if (await exists(fn)) result.push(fn);
    }
  }
  return result;
};

async function launcherCandidates(fn) {
  const dirs = [];

  try {
    const real = await fs.realpath(fn);
    const dir = path.dirname(real);
    dirs.push(dir, path.dirname(dir));
  } catch {}

  try {
    const stat = await fs.stat(fn);
    if (stat.size < 16384) {
      const text = await fs.readFile(fn, 'utf8');
      const re = /["']?((?:\/|[A-Za-z]:[\\/])[^"'\s]+?[\\/]ghidraRun(?:\.bat)?)["']?/g;
      for (const match of text.matchAll(re)) {
        dirs.push(path.dirname(match[1]));
      }
    }
  } catch {}

  return dirs;
};

function directCandidates() {
  const home = os.homedir();
  return [
    '/opt/homebrew/Cellar/ghidra',
    '/usr/local/Cellar/ghidra',
    '/opt/homebrew/opt/ghidra',
    '/usr/local/opt/ghidra',
    '/home/linuxbrew/.linuxbrew/Cellar/ghidra',
    '/opt/ghidra',
    '/usr/local/ghidra',
    '/usr/share/ghidra',
    '/snap/ghidra/current',
    path.join(home, 'ghidra'),
  ];
};

function scanBases() {
  const home = os.homedir();
  const bases = [
    home,
    path.join(home, 'Downloads'),
    path.join(home, 'tools'),
    '/opt',
    '/usr/local',
    '/usr/share',
    '/Applications',
  ];
  if (isWindows) {
    const sysDrive = process.env.SystemDrive || 'C:';
    bases.push(
      `${sysDrive}\\`,
      process.env.ProgramFiles || `${sysDrive}\\Program Files`,
      path.join(home, 'Desktop'),
    );
  }
  return bases;
};

async function commonCandidates() {
  const result = [...directCandidates()];
  for (const base of scanBases()) {
    let entries;
    try {
      entries = await fs.readdir(base);
    } catch {
      continue;
    }
    for (const name of entries) {
      if (/^ghidra/i.test(name)) result.push(path.join(base, name));
    }
  }
  return result;
};

async function getGhidraDirFallback() {
  const fromEnv = process.env.GHIDRA_INSTALL_DIR;
  if (fromEnv) {
    const root = await findGhidraRoot(fromEnv, 3);
    if (root) return root;
  }

  for (const fn of await launchersFromPath()) {
    for (const dir of await launcherCandidates(fn)) {
      const root = await findGhidraRoot(dir, 3);
      if (root) return root;
    }
  }

  for (const candidate of await commonCandidates()) {
    const root = await findGhidraRoot(candidate, 4);
    if (root) return root;
  }

  return null;
};

async function getGhidraDir() {
  const dir = await getGhidraDirLegacy() || await getGhidraDirFallback();
  if (!dir) {
    throw new Error(
      'Unable to find a Ghidra installation ' +
      '(tried GHIDRA_INSTALL_DIR, PATH, and common install locations).\n' +
      'Set GHIDRA_INSTALL_DIR to the directory containing ghidraRun and retry.'
    );
  }
  return dir;
};

async function readAppProps(installRoot) {
  const fn = path.join(installRoot, 'Ghidra', 'application.properties');
  const props = {};
  const text = await fs.readFile(fn, 'utf8').catch(() => '');
  for (const line of text.split('\n')) {
    const idx = line.indexOf('=');
    if (idx > 0 && !line.trimStart().startsWith('#')) {
      props[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    }
  }
  return props;
};

async function findSettingsDir(installRoot) {
  const props = await readAppProps(installRoot);
  const version = props['application.version'];
  const release = props['application.release.name'] || 'PUBLIC';
  if (!version) return null;

  const home = os.homedir();
  const modern = `ghidra_${version}_${release}`;
  const legacy = `.ghidra_${version}_${release}`;

  const candidates = [];
  if (process.env.XDG_CONFIG_HOME) {
    candidates.push(path.join(process.env.XDG_CONFIG_HOME, 'ghidra', modern));
  }
  if (process.platform === 'darwin') {
    candidates.push(path.join(home, 'Library', 'ghidra', modern));
  } else if (isWindows) {
    if (process.env.APPDATA) {
      candidates.push(path.join(process.env.APPDATA, 'ghidra', modern));
    }
  } else {
    candidates.push(path.join(home, '.config', 'ghidra', modern));
  }
  candidates.push(path.join(home, '.ghidra', legacy));

  for (const dir of candidates) {
    if (await exists(dir)) return dir;
  }

  return null;
};

module.exports = { getGhidraDir, findSettingsDir };
