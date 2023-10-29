const fs = require('fs/promises');
const { exists } = require('./myFs');
const path = require('path');
const { getOptions } = require('./options');

const configPath = path.resolve(__dirname, 'config.json');

async function getConfig() {
  if (!await exists(configPath)) {
    await fs.writeFile(configPath, '{}');
  }
  const config = JSON.parse(await fs.readFile(configPath).then(res => res.toString()));
  return config;
}

async function loadConfig() {
  const decamelize = await import('decamelize').then(res => res.default);
  const config = await getConfig();
  for (const [key, value] of Object.entries(config)) {
    const envKey = 'GHIDRAJS_' + decamelize(key.replaceAll('-', '')).toUpperCase();
    if (!process.env.hasOwnProperty(envKey)) {
      process.env[envKey] ||= value;
    }
  }
}

async function updateConfig(obj) {
  const config = await getConfig();
  const options = getOptions();
  const optionsKeys = [...Object.keys(options).map(e => e.replaceAll('-', '')), 'projectLocation', 'projectName'];
  const resObj = {};
  for (const [key, value] of Object.entries(obj)) {
    if (!optionsKeys.includes(key)) {
      console.error('[!] Unknown property', key);
    }
    else {
      resObj[key] = value;
    }
  }
  await fs.writeFile(configPath, JSON.stringify({ ...config, ...resObj }, null, 2));
}

async function getConfigValue(key) {
  const config = await getConfig();
  return config[key];
}

module.exports = { getConfig, loadConfig, updateConfig, getConfigValue };
