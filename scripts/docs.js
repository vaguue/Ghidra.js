const path = require('path');

const unzipper = require('unzipper');
const cheerio = require('cheerio');

const { getGhidraDir } = require('./search');

async function openJavadoc() {
  const installDir = await getGhidraDir();
  const zipPath = path.join(installDir, 'docs', 'GhidraAPI_javadoc.zip');
  try {
    return await unzipper.Open.file(zipPath);
  } catch {
    throw new Error(`could not open the Ghidra API javadoc at ${zipPath}`);
  }
};

const entryToFqn = (p) => p.replace(/^api\//, '').replace(/\.html$/, '').replace(/\//g, '.');

// Find javadoc entries matching a class query: a fully-qualified name
// (ghidra.app.decompiler.DecompInterface), a slash path, or a simple class name.
function findEntries(dir, query) {
  const classes = dir.files.filter((f) =>
    /^api\/.+\.html$/.test(f.path) &&
    !/(package-summary|package-tree|package-use|class-use|-)\b/.test(path.basename(f.path)) &&
    !f.path.includes('/class-use/'));

  const asPath = query.replace(/\./g, '/');
  const exact = classes.filter((f) => f.path === `api/${asPath}.html`);
  if (exact.length) return exact;

  const wanted = query.split(/[./]/).pop().toLowerCase();
  return classes.filter((f) => path.basename(f.path, '.html').toLowerCase() === wanted);
};

function wrap(text, width = 88, indent = '') {
  const words = String(text).replace(/\s+/g, ' ').trim().split(' ');
  const lines = [];
  let cur = '';
  for (const w of words) {
    if (cur && (cur + ' ' + w).length > width) { lines.push(cur); cur = w; }
    else cur = cur ? cur + ' ' + w : w;
  }
  if (cur) lines.push(cur);
  return lines.map((l) => indent + l).join('\n');
};

// Pull the method summary rows (return type, signature, one-line description)
// from the modern javadoc grid layout.
function methodSummary($) {
  // The grid emits .col-first (type), .col-second (signature), .col-last (desc)
  // per row in document order; select them regardless of nesting and group in 3s.
  const cells = $('#method-summary-table').find('.col-first, .col-second, .col-last').toArray()
    .map((el) => ({ cls: $(el).attr('class') || '', text: $(el).text().replace(/\s+/g, ' ').trim() }))
    .filter((c) => !/table-header/.test(c.cls));

  const rows = [];
  for (let i = 0; i + 2 < cells.length + 1; i += 3) {
    rows.push({ type: cells[i]?.text || '', sig: cells[i + 1]?.text || '', desc: cells[i + 2]?.text || '' });
  }
  return rows;
};

function methodDetails($, only) {
  const out = [];
  $('#method-detail section.detail, section.method-details section.detail').each((_, sec) => {
    const $sec = $(sec);
    const name = $sec.find('h3, h2').first().text().trim();
    if (only && name.toLowerCase() !== only.toLowerCase()) return;
    const sig = $sec.find('.member-signature, .memberSignature').first().text().replace(/\s+/g, ' ').trim();
    const desc = $sec.find('.block').first().text().trim();
    out.push({ name, sig, desc });
  });
  return out;
};

async function renderClass(query, { full = false, method } = {}) {
  const dir = await openJavadoc();
  const matches = findEntries(dir, query);

  if (matches.length === 0) {
    throw new Error(`no class matching "${query}" in the Ghidra API javadoc`);
  }
  if (matches.length > 1) {
    const list = matches.map((f) => '  ' + entryToFqn(f.path)).sort().join('\n');
    throw new Error(`"${query}" is ambiguous - re-run with a fully-qualified name:\n${list}`);
  }

  const html = (await matches[0].buffer()).toString('utf8');
  const $ = cheerio.load(html);
  const fqn = entryToFqn(matches[0].path);

  const lines = [];
  lines.push(fqn);
  const classDesc = $('section.class-description .block, .description .block').first().text().trim();
  if (classDesc && !method) { lines.push(''); lines.push(wrap(classDesc)); }

  if (method || full) {
    const details = methodDetails($, method);
    if (method && details.length === 0) {
      throw new Error(`no method "${method}" on ${fqn}`);
    }
    for (const m of details) {
      lines.push('');
      lines.push(m.sig || m.name);
      if (m.desc) lines.push(wrap(m.desc, 88, '    '));
    }
  }
  else {
    const rows = methodSummary($);
    lines.push('');
    lines.push(rows.length ? 'Methods:' : '(no declared methods)');
    for (const r of rows) {
      const ret = r.type ? `${r.type} ` : '';
      lines.push(`  ${ret}${r.sig}`);
    }
    lines.push('');
    lines.push(`Use --full for descriptions, or --method <name> for one method.`);
  }

  return lines.join('\n');
};

module.exports = { renderClass };
