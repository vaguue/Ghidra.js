const fs = require('fs/promises');

const platformMap = {
  darwin: 'macos',
  linux: 'linux',
  win32: 'windows',
};

function systemId() {
  const arch = process.env.npm_config_arch || process.arch;
  const platform = platformMap[process.env.npm_config_platform || process.platform];
  if (!platform) {
    throw new Error('Unsupported platform');
  }
  const platformId = [`${platform}`];
  if (arch === 'arm') {
    const fallback = process.versions.electron ? '7' : '6';
    platformId.push(`armv${process.env.npm_config_arm_version || process.config.variables.arm_version || fallback}`);
  } else if (arch === 'arm64') {
    platformId.push(`arm64v${process.env.npm_config_arm_version || '8'}`);
  } else {
    platformId.push(arch);
  }
  return platformId.join('-');
}

const exists = fn => fs.access(fn).then(() => true).catch(() => false) 

module.exports = { exists, systemId };
