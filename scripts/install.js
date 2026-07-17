const path = require('path');
const fs = require('fs/promises');
const { createReadStream } = require('fs');
const { pipeline } = require('stream/promises');

const unzipper = require('unzipper');

const { systemId, exists } = require('./sys');
const { getGhidraDir, findSettingsDir } = require('./search');

async function getLatestRelease({ runtime }) {
  const axios = require('axios');
  const [platform] = systemId().split('-');
  try {
    const url = `https://api.github.com/repos/vaguue/Ghidra.js/releases/latest`;
    const response = await axios.get(url, {
      responseType: 'json',
      headers: {
        'Accept': 'application/vnd.github.v3+json',
      }
    });

    const { assets } = response.data;

    const extUrl = assets.find(e => {
      const name = e.name.toLowerCase();
      return name.includes('.zip') && name.includes(runtime) && name.includes(platform);
    });

    const download = await axios.get(extUrl.browser_download_url, {
      responseType: 'stream',
    });
    return download.data;
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

function describeSource({
  isLocal = Boolean(process.env.GHIDRAJS_INSTALL_LOCAL),
  runtime = process.env.GHIDRAJS_RUNTIME || 'javet',
} = {}) {
  const [platform] = systemId().split('-');
  return isLocal
    ? `local dist/${runtime}/*.zip`
    : `latest GitHub release (${runtime}, ${platform})`;
};

async function resolveTarget(installDir) {
  const installDirExtensions = path.resolve(installDir, 'Ghidra', 'Extensions');
  const settingsDir = await findSettingsDir(installDir);

  if (settingsDir) {
    return { outPath: path.join(settingsDir, 'Extensions'), installDirExtensions };
  }
  if (!await exists(installDirExtensions)) {
    throw new Error(
      `No user settings directory found for ${installDir} ` +
      'and it has no Ghidra/Extensions directory - ' +
      'try launching Ghidra once and rerunning the installation'
    );
  }
  return { outPath: installDirExtensions, installDirExtensions };
};

async function install(opts = {}) {
  const dryRun = opts.dryRun ?? Boolean(process.env.GHIDRAJS_DRY_RUN);

  const installDir = await getGhidraDir(opts);
  console.log(`[*] Found Ghidra installation at ${installDir}`);

  const { outPath, installDirExtensions } = await resolveTarget(installDir);

  const staleDirs = [];
  for (const dir of new Set([outPath, installDirExtensions])) {
    const checkPath = path.join(dir, 'Ghidra.js');
    if (await exists(checkPath)) staleDirs.push(checkPath);
  }

  if (dryRun) {
    console.log('[dry-run] No changes will be made. Plan:');
    console.log(`[dry-run]   source:  ${describeSource(opts)}`);
    console.log(`[dry-run]   install: ${outPath}`);
    for (const checkPath of staleDirs) {
      console.log(`[dry-run]   remove:  ${checkPath}`);
    }
    if (staleDirs.length === 0) {
      console.log('[dry-run]   remove:  (nothing existing to remove)');
    }
    return;
  }

  const input = await getInputStream(opts);
  await fs.mkdir(outPath, { recursive: true });
  for (const checkPath of staleDirs) {
    await fs.rm(checkPath, { recursive: true });
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
