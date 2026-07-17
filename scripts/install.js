const path = require('path');
const fs = require('fs/promises');
const { createReadStream } = require('fs');
const { pipeline } = require('stream/promises');

const unzipper = require('unzipper');

const { systemId, exists } = require('./sys');
const { getGhidraDir, findSettingsDir } = require('./search');

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
    console.log('[*] Trying to install from local .zip');
    return createReadStream(path.resolve(dist, fn));
  }
  else {
    return getLatestRelease({ runtime });
  }
};

async function install(opts = {}) {
  const input = await getInputStream(opts);
  const installDir = await getGhidraDir(opts);
  console.log(`[*] Found Ghidra installation at ${installDir}`);

  const installDirExtensions = path.resolve(installDir, 'Ghidra', 'Extensions');
  const settingsDir = await findSettingsDir(installDir);

  let outPath;
  if (settingsDir) {
    outPath = path.join(settingsDir, 'Extensions');
    await fs.mkdir(outPath, { recursive: true });
  }
  else {
    if (!await exists(installDirExtensions)) {
      throw new Error(
        `No user settings directory found for ${installDir} ` +
        'and it has no Ghidra/Extensions directory - ' +
        'try launching Ghidra once and rerunning the installation'
      );
    }
    outPath = installDirExtensions;
  }

  for (const dir of new Set([outPath, installDirExtensions])) {
    const checkPath = path.join(dir, 'Ghidra.js');
    if (await exists(checkPath)) {
      await fs.rm(checkPath, { recursive: true })
    }
  }

  const output = unzipper.Extract({ path: outPath })
  console.log('[*] Downloading release');
  await pipeline(input, output);
  console.log(`[*] Installed Ghidra.js to ${outPath}`);
};

module.exports = { install };

if (require.main === module) {
  install().then(() => process.exit(0)).catch(console.error);
}
