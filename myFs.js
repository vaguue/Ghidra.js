const fs = require('fs/promises');

function exists(fn) {
  return fs.access(fn).then(() => true).catch(() => false;)
}

module.exports = { exists };
