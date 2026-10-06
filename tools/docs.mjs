// `npm run docs`: the public rule pages, docs/rules/<lang>/<name>.md, and their index,
// docs/rules/README.md. Qualor links each finding to its page on GitHub, so the paths are fixed.
//
// A page has two kinds of text. Generated from the rule's YAML: the title, the header line (key,
// kind, severity, CWE and OWASP links), the hotspot note, the frameworks, the references and the
// link to the test file. Hand-written: the sections between `<!-- begin: <section> -->` and
// `<!-- end: <section> -->` (what it finds, why it matters, example, how to fix, known limits),
// which `npm run docs` keeps from the existing page. A new rule gets a page with TODO lines in
// those sections.
//
//   node tools/docs.mjs           write every page and the index
//   node tools/docs.mjs --check   (part of `npm run check`) exit 1 when a rule has no page, a page
//                                 has no rule, a section is not written, or a page is out of date
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LANGS, readRule, ruleFiles } from './rules.mjs';

export const DOCS = 'docs/rules';
export const REPOSITORY = 'https://github.com/qualor-dev/qualor-rules';

/** The hand-written sections of a page, in page order, and where each one goes. */
export const SECTIONS = Object.freeze([
  { id: 'what-it-finds', heading: 'What it finds' },
  { id: 'why-it-matters', heading: 'Why it matters' },
  { id: 'example', heading: 'Example' },
  { id: 'how-to-fix', heading: 'How to fix' },
  { id: 'known-limits', heading: 'Known limits' },
]);
export const TODO = 'TODO: write this section (see .claude/skills/write-rules/rule-procedure.md, step 7).';

export const LANG_NAMES = Object.freeze({ js: 'JavaScript and TypeScript', python: 'Python', java: 'Java', go: 'Go' });

/** Fence languages of the examples and the file extension OpenGrep needs to parse them. */
export const FENCES = Object.freeze({
  js: { javascript: '.js', jsx: '.jsx', typescript: '.ts', tsx: '.tsx' },
  python: { python: '.py' },
  java: { java: '.java' },
  go: { go: '.go' },
});

/** OWASP Top 10 categories that rules name (metadata.owasp), with their pages. */
export const OWASP = Object.freeze({
  'A01:2021': ['Broken Access Control', 'https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/'],
  'A02:2021': ['Cryptographic Failures', 'https://top10.owasp.org/2021/A02_2021-Cryptographic_Failures/'],
  'A03:2021': ['Injection', 'https://top10.owasp.org/2021/A03_2021-Injection/'],
  'A04:2021': ['Insecure Design', 'https://top10.owasp.org/2021/A04_2021-Insecure_Design/'],
  'A05:2021': ['Security Misconfiguration', 'https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/'],
  'A06:2021': ['Vulnerable and Outdated Components', 'https://top10.owasp.org/2021/A06_2021-Vulnerable_and_Outdated_Components/'],
  'A07:2021': ['Identification and Authentication Failures', 'https://top10.owasp.org/2021/A07_2021-Identification_and_Authentication_Failures/'],
  'A08:2021': ['Software and Data Integrity Failures', 'https://top10.owasp.org/2021/A08_2021-Software_and_Data_Integrity_Failures/'],
  'A09:2021': ['Security Logging and Monitoring Failures', 'https://top10.owasp.org/2021/A09_2021-Security_Logging_and_Monitoring_Failures/'],
  'A10:2021': ['Server-Side Request Forgery', 'https://top10.owasp.org/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'],
  'A01:2025': ['Broken Access Control', 'https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/'],
  'A02:2025': ['Security Misconfiguration', 'https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/'],
  'A03:2025': ['Software Supply Chain Failures', 'https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/'],
  'A04:2025': ['Cryptographic Failures', 'https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/'],
  'A05:2025': ['Injection', 'https://top10.owasp.org/2025/A05_2025-Injection/'],
  'A06:2025': ['Insecure Design', 'https://top10.owasp.org/2025/A06_2025-Insecure_Design/'],
  'A07:2025': ['Authentication Failures', 'https://top10.owasp.org/2025/A07_2025-Authentication_Failures/'],
  'A08:2025': ['Software or Data Integrity Failures', 'https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/'],
  'A09:2025': ['Security Logging and Alerting Failures', 'https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/'],
  'A10:2025': ['Mishandling of Exceptional Conditions', 'https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/'],
});

/**
 * Readable names of metadata.frameworks entries. A name not listed here (a package path such as
 * `net/http` or `java.util.zip`) is shown as code.
 */
export const FRAMEWORKS = Object.freeze({
  aiohttp: 'aiohttp',
  axios: 'axios',
  bleach: 'bleach',
  bluemonday: 'bluemonday',
  chi: 'chi',
  'commons-compress': 'Apache Commons Compress',
  'commons-io': 'Apache Commons IO',
  dbapi: 'Python DB-API (PEP 249) drivers',
  defusedxml: 'defusedxml',
  dill: 'dill',
  django: 'Django',
  'django-hosts': 'django-hosts',
  dom4j: 'dom4j',
  echo: 'Echo',
  ejs: 'EJS',
  'escape-string-regexp': 'escape-string-regexp',
  express: 'Express',
  fastapi: 'FastAPI',
  fastify: 'Fastify',
  fetch: 'fetch()',
  flask: 'Flask',
  freemarker: 'Apache FreeMarker',
  gin: 'Gin',
  'gorilla/mux': 'gorilla/mux',
  gorm: 'GORM',
  got: 'Got',
  handlebars: 'Handlebars',
  httpx: 'HTTPX',
  'jakarta-el': 'Jakarta Expression Language',
  'java-net': 'java.net (URL, URLConnection)',
  'java-net-http': 'java.net.http (HttpClient)',
  'java-serialization': 'Java serialization (ObjectInputStream)',
  'jax-rs': 'Jakarta REST (JAX-RS)',
  jaxp: 'JAXP (javax.xml parsers and transformers)',
  jdbc: 'JDBC',
  jdom: 'JDOM',
  jinja2: 'Jinja',
  jndi: 'JNDI (javax.naming.directory)',
  jpa: 'Jakarta Persistence (JPA)',
  jsonpickle: 'jsonpickle',
  knex: 'Knex.js',
  lodash: 'Lodash',
  lxml: 'lxml',
  markupsafe: 'MarkupSafe',
  mongodb: 'MongoDB Node.js driver',
  mongoose: 'Mongoose',
  mvel: 'MVEL',
  mysql2: 'mysql2',
  nextjs: 'Next.js',
  nh3: 'nh3',
  'node-child-process': 'Node.js child_process',
  'node-fs': 'Node.js fs',
  'node-http': 'Node.js http',
  'node-http2': 'Node.js http2',
  'node-https': 'Node.js https',
  'node-tls': 'Node.js tls',
  'node-vm': 'Node.js vm',
  nunjucks: 'Nunjucks',
  ognl: 'OGNL',
  pg: 'node-postgres (pg)',
  prisma: 'Prisma',
  psycopg: 'psycopg',
  pug: 'Pug',
  pyyaml: 'PyYAML',
  react: 'React',
  requests: 'Requests',
  sequelize: 'Sequelize',
  servlet: 'Jakarta Servlet',
  'spring-expression': 'Spring Expression Language (SpEL)',
  'spring-jdbc': 'Spring JDBC (JdbcTemplate)',
  'spring-ldap': 'Spring LDAP',
  'spring-mvc': 'Spring MVC',
  'spring-web-client': 'Spring RestTemplate, RestClient and WebClient',
  sqlalchemy: 'SQLAlchemy',
  starlette: 'Starlette',
  thymeleaf: 'Thymeleaf',
  typeorm: 'TypeORM',
  undici: 'undici',
  urllib3: 'urllib3',
  velocity: 'Apache Velocity',
  werkzeug: 'Werkzeug',
  'xml-decoder': 'java.beans.XMLDecoder',
});

const KINDS = { issue: 'Issue', hotspot: 'Security hotspot' };
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const cweUrl = (cwe) => `https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`;
const pagePath = (lang, name) => `${DOCS}/${lang}/${name}.md`;

/** Every rule with what its page needs, sorted by language (LANGS order) and name. */
export function docRules(root) {
  const out = [];
  for (const file of ruleFiles(root)) {
    const r = readRule(root, file);
    if (r.rule === undefined) continue;
    const [, lang, category, base] = file.split('/');
    const name = base.replace(/\.yml$/, '');
    const tests = LANGS[lang].tests
      .map((ext) => `rules/${lang}/${category}/${name}${ext}`)
      .filter((t) => existsSync(path.join(root, t)));
    out.push({ file, lang, name, key: `qualor:${lang}/${name}`, id: r.rule.id, meta: r.rule.metadata ?? {}, tests, page: pagePath(lang, name) });
  }
  const order = Object.keys(LANGS);
  return out.sort((a, b) => order.indexOf(a.lang) - order.indexOf(b.lang) || a.name.localeCompare(b.name));
}

/** The hand-written sections of a page's text, by id (undefined for a section it lacks). */
export function handWritten(text) {
  const out = {};
  for (const { id } of SECTIONS) {
    const m = text?.match(new RegExp(`<!-- begin: ${id} -->\\n([\\s\\S]*?)\\n?<!-- end: ${id} -->`));
    if (m) out[id] = m[1].trim();
  }
  return out;
}

function owaspLinks(list) {
  return list.map((o) => {
    const known = OWASP[o];
    return known ? `[${o} ${known[0]}](${known[1]})` : o;
  });
}

const frameworkName = (f) => FRAMEWORKS[f] ?? `\`${f}\``;

/** The page of `rule`, keeping the hand-written sections of `existing` (the current page, if any). */
export function renderPage(rule, existing) {
  const { meta } = rule;
  const prose = handWritten(existing);
  const header = [
    `\`${rule.key}\``,
    KINDS[meta.kind] ?? meta.kind,
    `Severity: ${cap(meta.severity ?? '')}`,
    (meta.cwe ?? []).map((c) => `[${c}](${cweUrl(c)})`).join(', '),
  ];
  if ((meta.owasp ?? []).length > 0) header.push(`OWASP Top 10: ${owaspLinks(meta.owasp).join(', ')}`);
  const section = (id, heading) => [`## ${heading}`, '', `<!-- begin: ${id} -->`, prose[id] || TODO, `<!-- end: ${id} -->`, ''];
  const lines = [
    `<!-- Generated by tools/docs.mjs from ${rule.file}.`,
    '     Edit only the text between the begin and end markers: `npm run docs` rewrites the rest. -->',
    '',
    `# ${meta.title}`,
    '',
    header.join(' · '),
    '',
  ];
  if (meta.kind === 'hotspot') {
    lines.push(
      '> **Security hotspot.** This rule asks for a review: it marks code that is often safe and',
      '> sometimes not, and a person decides which. A hotspot never fails the quality gate.',
      '',
    );
  }
  for (const s of SECTIONS.slice(0, 4)) lines.push(...section(s.id, s.heading));
  lines.push('## Frameworks and APIs covered', '', ...(meta.frameworks ?? []).map((f) => `- ${frameworkName(f)}`), '');
  lines.push(...section('known-limits', 'Known limits'));
  lines.push('## References', '', ...(meta.sources ?? []).map((u) => `- <${u}>`), '');
  const tests = rule.tests.map((t) => `[\`${t}\`](../../../${t})`);
  const many = tests.length > 1;
  lines.push(
    '## Tests',
    '',
    `The test file${many ? 's' : ''} ${tests.join(' and ')} ${many ? 'hold' : 'holds'} every case the rule reports or accepts:`,
    'lines marked `ruleid:` must be reported and lines marked `ok:` must not. The known limits are',
    'marked `todoruleid:` (missed) and `todook:` (wrongly reported). `npm test` runs them with OpenGrep,',
    'and checks the example above as well.',
    '',
    `The rule: [\`${rule.file}\`](../../../${rule.file}), added in version ${meta.since}.`,
    '',
  );
  return lines.join('\n');
}

/** docs/rules/README.md: the index of every page. */
export function renderIndex(rules) {
  const lines = [
    '<!-- Generated by tools/docs.mjs from rules/: run `npm run docs` after changing a rule. -->',
    '',
    '# Qualor security rules',
    '',
    `The security rules of Qualor's \`qualor\` engine, ${rules.length} in all. Each page says what the rule finds, why`,
    'it matters, how to fix it, what the rule misses or may wrongly report, and shows a short example.',
    'Qualor links every finding to its page.',
    '',
    '- An **issue** is a finding the code should not keep: data from the request reaching a dangerous',
    '  call, or an unsafe setting. Issues count in the quality gate.',
    '- A **security hotspot** asks a person to review a use that is often safe and sometimes not. It',
    '  never fails the quality gate.',
    '',
    'The key `qualor:<lang>/<name>` is how Qualor names a rule; the rule itself is',
    '`rules/<lang>/<category>/<name>.yml`, with id `<lang>.<name>`.',
    '',
  ];
  for (const lang of Object.keys(LANGS)) {
    const list = rules.filter((r) => r.lang === lang);
    if (list.length === 0) continue;
    lines.push(`## ${LANG_NAMES[lang]}`, '', '| Rule | Title | Kind | Severity | CWE |', '|---|---|---|---|---|');
    for (const r of list) {
      const cwe = (r.meta.cwe ?? []).map((c) => `[${c}](${cweUrl(c)})`).join(', ');
      lines.push(`| [\`${r.key}\`](${r.lang}/${r.name}.md) | ${r.meta.title} | ${KINDS[r.meta.kind] ?? r.meta.kind} | ${cap(r.meta.severity ?? '')} | ${cwe} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

/**
 * The two code blocks of a page's example section: `{ noncompliant, compliant }`, each
 * `{ fence, code }` (the first fenced block after a line that starts with `**Noncompliant` or
 * `**Compliant`), or undefined when missing.
 */
export function examples(text) {
  const example = handWritten(text).example ?? '';
  const out = {};
  const re = /^\*\*(Noncompliant|Compliant)\b[^\n]*\n(?:(?!```)[^\n]*\n)*?```(\w+)\n([\s\S]*?)\n```/gm;
  for (const m of example.matchAll(re)) {
    const key = m[1].toLowerCase();
    if (out[key] === undefined) out[key] = { fence: m[2], code: `${m[3]}\n` };
  }
  return out;
}

/** The problems of the docs of `root`, and the files `npm run docs` would write (path → text). */
export function docsState(root) {
  const rules = docRules(root);
  const problems = [];
  const files = new Map();
  for (const rule of rules) {
    const full = path.join(root, rule.page);
    const existing = existsSync(full) ? readFileSync(full, 'utf8') : undefined;
    const text = renderPage(rule, existing);
    files.set(rule.page, text);
    if (existing === undefined) {
      problems.push(`${rule.file}: no page ${rule.page} (run npm run docs, then write its sections)`);
      continue;
    }
    if (existing !== text) problems.push(`${rule.page}: out of date with ${rule.file} (run npm run docs)`);
    const prose = handWritten(existing);
    const todo = SECTIONS.filter(({ id }) => !prose[id] || prose[id].includes(TODO)).map(({ id }) => id);
    if (todo.length > 0) problems.push(`${rule.page}: write the section(s) ${todo.join(', ')}`);
    if (todo.includes('example')) continue;
    const ex = examples(existing);
    for (const key of ['noncompliant', 'compliant']) {
      if (ex[key] === undefined) problems.push(`${rule.page}: the example has no **${cap(key)}** code block`);
      else if (!Object.hasOwn(FENCES[rule.lang], ex[key].fence)) {
        problems.push(`${rule.page}: the ${key} example is \`\`\`${ex[key].fence}; use one of ${Object.keys(FENCES[rule.lang]).join(', ')}`);
      }
    }
  }
  const index = `${DOCS}/README.md`;
  const indexText = renderIndex(rules);
  files.set(index, indexText);
  const current = existsSync(path.join(root, index)) ? readFileSync(path.join(root, index), 'utf8') : undefined;
  if (current !== indexText) problems.push(`${index}: out of date (run npm run docs)`);
  // Pages without a rule, and anything else in docs/rules/.
  const docs = path.join(root, DOCS);
  if (existsSync(docs)) {
    for (const e of readdirSync(docs, { withFileTypes: true })) {
      const rel = `${DOCS}/${e.name}`;
      if (e.isFile() && e.name === 'README.md') continue;
      if (!e.isDirectory() || !Object.hasOwn(LANGS, e.name)) {
        problems.push(`${rel}: not a language directory (${Object.keys(LANGS).join(', ')})`);
        continue;
      }
      for (const f of readdirSync(path.join(docs, e.name), { withFileTypes: true })) {
        const page = `${rel}/${f.name}`;
        if (!files.has(page)) problems.push(`${page}: no rule rules/${e.name}/<category>/${f.name.replace(/\.md$/, '')}.yml has this page`);
      }
    }
  }
  return { problems, files };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const check = process.argv.includes('--check');
  const { problems, files } = docsState(root);
  if (check) {
    for (const p of problems) console.error(p);
    console.log(problems.length === 0 ? `docs: ok (${files.size - 1} pages)` : `docs: ${problems.length} problem(s)`);
    process.exit(problems.length === 0 ? 0 : 1);
  }
  for (const [rel, text] of files) {
    mkdirSync(path.dirname(path.join(root, rel)), { recursive: true });
    writeFileSync(path.join(root, rel), text);
  }
  // What only a person can fix: sections to write, pages without a rule.
  const left = docsState(root).problems;
  for (const p of left) console.error(p);
  console.log(`docs: wrote ${files.size - 1} pages and ${DOCS}/README.md${left.length > 0 ? `; ${left.length} problem(s) left` : ''}`);
  process.exit(left.length === 0 ? 0 : 1);
}
