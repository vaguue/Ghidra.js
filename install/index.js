const path = require('path');
const fs = require('fs/promises');
const { createReadStream } = require('fs');
const { pipeline } = require('stream/promises');

const unzipper = require('unzipper');

const { systemId, exists } = require('./sys');

async function isGhidraDir(dir) {
  if (
    await exists(path.resolve(dir, 'ghidraRun')) &&
    await exists(path.resolve(dir, 'Ghidra', 'Extensions'))
  ) {
    return true;
  }
};

async function getGhidraDir() {
  const fromEnv = process.env.GHIDRA_INSTALL_DIR
  if (fromEnv && await isGhidraDir(fromEnv)) {
    return path.resolve(fromEnv);
  }

  const pathDirs = process.env.PATH.split(':');
  let fromPath = null;
  for (const dir of pathDirs) {
    if (await isGhidraDir(dir)) {
      fromPath = dir;
      break;
    }
  }

  if (!fromPath) {
    throw new Error('Unable to find Ghidra installation directory - exiting');
  }
  return path.resolve(fromPath);
};

async function getLatestRelease({ runtime }) {
  const got = await import('got').then(res => res.default);
  const [platform] = systemId().split('-');
  try {
    const url = `https://api.github.com/repos/vaguue/Ghidra.js/releases/latest`;
    const response = await got(url, {
      responseType: 'json',
      headers: {
        'Accept': 'application/vnd.github.v3+json',
      }
    });

    const release = response.body;
    const { assets } = release;

    const extUrl = assets.find(e => {
      const name = e.name.toLowerCase();
      return name.includes('.zip') && name.includes(runtime) && name.includes(platform);
    }); 

    return got.stream(extUrl.browser_download_url);
  } catch (error) {
    console.error(error);
    throw error;
  }
}

async function getInputStream({ 
  isLocal = Boolean(process.env.GHIDRAJS_INSTALL_LOCAL),
  runtime = process.env.GHIDRAJS_RUNTIME || 'javet',
}) {
  if (isLocal) {
    const dist = path.resolve(process.cwd(), 'dist', runtime);
    const fn = await fs.readdir(dist).then(ch => ch.find(e => e.includes('.zip')));
    return createReadStream(path.resolve(dist, fn));
  }
  else {
    return getLatestRelease({ runtime });
  }
};

async function install(opts = {}) {
  const input = await getInputStream(opts);
  const installDir = await getGhidraDir(opts);
  const outPath = path.resolve(installDir, 'Ghidra', 'Extensions');
  const checkPath = path.join(outPath, 'Ghidra.js');
  if (await exists(checkPath)) {
    await fs.rm(checkPath, { recursive: true })
  }
  const output = unzipper.Extract({ path: outPath })
  console.log('[*] Downloading release');
  await pipeline(input, output);
  console.log('[*] Installed Ghidra.js');
};

module.exports = { install };

if (require.main === module) {
  install().then(() => process.exit(0)).catch(console.error);
}
