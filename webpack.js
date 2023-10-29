const path = require('path');
const os = require('os');

const webpack = require('webpack');
const _ = require('lodash');

const { exists } = require('./myFs');

const getConfig = (file, outputDir) => ({
  mode: 'production',
  entry: file,
  output: {
    path: outputDir,
    filename: '[name].min.js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', {
                targets: {
                  esmodules: false
                },
                useBuiltIns: 'entry',
                corejs: 3
              }]
            ]
          },
        },
      },
    ],
  },
});

async function build(file, outputDir = os.tmpdir()) {
  let config = getConfig(file, path.resolve(outputDir));
  const customConfigPath = path.resolve(process.cwd(), 'webpack.config.js'); 
  if (await exists(customConfigPath)) {
    config = _.merge(config, require(customConfigPath));
  }
  return new Promise((resolve, reject) => {
    webpack(config, (err, stats) => {
      if (err || stats.hasErrors()) {
        reject(err);
      }
      const outputPath = stats.toJson().outputPath;
      const assets = stats.toJson().assets;
      const outputFile = path.join(outputPath, assets[0].name)
      resolve([outputFile, stats]);
    });
  });
}

module.exports = { build };
