const path = require('path');
const fs = require('fs/promises');
const { exists } = require('./myFs');
const { createReadStream } = require('fs');
const { pipeline } = require('stream/promises');
const unzipper = require('unzipper');
const { updateConfig } = require('./config');
require('dotenv').config();

const isLocal = Boolean(process.env.GHIDRA_JS_INSTALL_LOCAL);
const isRhino = Boolean(process.env.GHIDRA_JS_USE_RHINO);

async function isGhidraDir(dir) {
  try {
    const ch = await fs.readdir(dir);
    if (
      ch.includes('ghidraRun') && 
      ch.includes('Ghidra') && 
      await fs.readdir(path.resolve(dir, 'Ghidra')).then(res => res.includes('Extensions'))
    ) {
      return true;
    }
  } catch(err) { }
  return false;
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

async function getLatestRelease() {
  const got = await import('got').then(res => res.default);
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
    const extUrl = isRhino ? assets.find(e => e.name.includes('.zip') && e.name.toLowerCase().includes('rhino')) : 
                             assets.find(e => e.name.includes('.zip') && e.name.toLowerCase().includes('graal'));
    return got.stream(extUrl.browser_download_url);
  } catch (error) {
    console.error(error);
  }
}

async function getInputStream() {
  if (isLocal) {
    const dist = path.resolve(process.cwd(), 'dist');
    const fn = await fs.readdir(dist).then(ch => ch.find(e => e.includes('.zip')));
    return createReadStream(path.resolve(dist, fn));
  }
  else {
    return getLatestRelease();
  }
};

async function install() {
  const input = await getInputStream();
  const installDir = await getGhidraDir();
  const outPath = path.resolve(installDir, 'Ghidra', 'Extensions');
  const checkPath = path.join(outPath, 'Ghidra.js');
  if (await exists(checkPath)) {
    await fs.rmdir(checkPath, { recursive: true })
  }
  const output = unzipper.Extract({ path: outPath })
  await pipeline(input, output);
  console.log('[*] Installed Ghidra.js');
  await updateConfig({ installDir });
  console.log('[*] Saved Ghidra installation dir at', installDir);
};

install().then(() => process.exit(0)).catch(console.error);
