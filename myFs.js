const fs = require('fs/promises');

const exists = fn => fs.access(fn).then(() => true).catch(() => false) 

module.exports = { exists };
