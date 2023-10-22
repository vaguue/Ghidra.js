const os = require('os');
const webpack = require('webpack');

const getConfig = (file, outputDir = os.tmpdir()) => {
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
            presets: ['@babel/preset-env'],
          },
        },
      },
    ],
  },
}

async function build(file, outputDir) {
  const config = getConfig(file, outputDir);
  return new Promise((resolve, reject) => {
    webpack(config, (err, stats) => {
      if (err || stats.hasErrors()) {
        reject(err);
      }
      resolve(stats);
    });
  });
}

module.exports = { build };
