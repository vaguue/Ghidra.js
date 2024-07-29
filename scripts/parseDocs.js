const axios = require('axios');
const cheerio = require('cheerio');

function convertType(str) {
  if (str == 'int' || str == 'long' || str == 'java.lang.Long') return 'number';
  if (str == 'java.lang.String' || str == 'protected java.lang.String') return 'string';

  return str;
}

function fromTable($, p) {
  const res = [];

  $(p).find('table.memberSummary > tbody > tr').each(function(i) {
    if (i == 0) return;
    const tr = $(this);
    const ret = convertType(tr.children().eq(0).text());
    let [name, args] = tr.children().eq(1).text().split('(');
    args = args.slice(0, -1);
    args = args.split(',')
      .map(arg => arg
        .split(String.fromCharCode(0xa0))
        .filter(e => e.length > 0)
        .map(e => e.replace(/\s/g, ''))
        .reverse()
      )
      .map(arg => [arg[0], convertType(arg[1])].filter(e => e?.length > 0).join(': '))
      .join(', ')
    ;

    res.push(`${name}(${args}): ${ret};`);
  });

  return res;
}

function toInterface($) {
  const a = $('#method\\.summary').first()[0];
  const li = $(a).parent()[0];

  const defs = fromTable($, li);

  const title = $('h2.title').first().text().split(' ')[1];

  const res = `export interface ${title} {\n${defs.map(e => '  ' + e).join('\n')}\n}`;

  return res;
}

async function parsePage(url, withUrl = true) {
  const $ = await cheerio.load(await axios.get(url).then(resp => resp.data));

  let iface = toInterface($).replace(/\u200B/g, '');

  if (withUrl) {
    iface = `// ${url}\n\n${iface}`;
  }

  console.log(iface);
}

parsePage('https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/LanguageID.html').catch(console.error);
