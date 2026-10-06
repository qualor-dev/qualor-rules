// The safe-setting exclusions of rules/java/xxe/xxe.yml, generated from two tables.
//
//   node tools/xxe-exclusions.mjs           rewrite the blocks between the markers in xxe.yml
//   node tools/xxe-exclusions.mjs --check   exit 1 when a block differs from its table
//
// Each settings row is one way to make a parser safe: statements on the factory, reader or
// builder ($F), in any order when `anyOrder` is set. Each row becomes a `pattern-not-inside`
// for every POSITION: before the use in the same block, in a try block before it, and, for a
// field, in a static block, a constructor or a method of the class. The settings are per factory:
// SETTINGS hold for the parsers, builders, readers and transformers, SCHEMA_SETTINGS for a
// SchemaFactory, which reads external schemas (xs:import, xs:include, schemaLocation) under
// ACCESS_EXTERNAL_SCHEMA and external DTDs under ACCESS_EXTERNAL_DTD, so it needs both. Each
// table fills its own block (BLOCKS). Reviewers review the tables and the templates;
// tools/xxe-exclusions.test.mjs fails when the YAML drifts from them.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const RULE = path.join(root, 'rules/java/xxe/xxe.yml');

const DOCTYPE = '"http://apache.org/xml/features/disallow-doctype-decl"';
const GENERAL = '"http://xml.org/sax/features/external-general-entities"';
const PARAMETER = '"http://xml.org/sax/features/external-parameter-entities"';
const LOAD_DTD = '"http://apache.org/xml/features/nonvalidating/load-external-dtd"';

/**
 * Safe settings; R is the receiver. Every row applies to every receiver in the five positions
 * (a setting a factory does not support would not compile). `stax: true` marks the StAX
 * properties, which are only kept out of the SAXParser and XMLReader blocks.
 */
export const SETTINGS = Object.freeze([
  { name: 'DOCTYPE declarations refused', stmts: [`R.setFeature(${DOCTYPE}, true);`] },
  { name: 'DOCTYPE declarations refused (boxed)', stmts: [`R.setFeature(${DOCTYPE}, Boolean.TRUE);`] },
  {
    name: 'external general and parameter entities and the external DTD all off',
    anyOrder: true,
    stmts: [`R.setFeature(${GENERAL}, false);`, `R.setFeature(${PARAMETER}, false);`, `R.setFeature(${LOAD_DTD}, false);`],
  },
  { name: 'external DTD and entity access denied (constant)', stmts: ['R.$SET(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");'] },
  { name: 'external DTD and entity access denied (name)', stmts: ['R.$SET("http://javax.xml.XMLConstants/property/accessExternalDTD", "");'] },
  ...['javax.xml.stream.XMLInputFactory.SUPPORT_DTD', '"javax.xml.stream.supportDTD"',
    'javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES', '"javax.xml.stream.isSupportingExternalEntities"']
    .flatMap((key) => ['false', 'Boolean.FALSE'].map((v) => ({ name: `StAX ${key} ${v}`, stax: true, stmts: [`R.setProperty(${key}, ${v});`] }))),
]);

const ACCESS_DTD = ['javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD', '"http://javax.xml.XMLConstants/property/accessExternalDTD"'];
const ACCESS_SCHEMA = ['javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA', '"http://javax.xml.XMLConstants/property/accessExternalSchema"'];

/**
 * Safe settings of a SchemaFactory: external DTDs and external schemas both denied, in any order,
 * each property named by its constant or its name. The rows of SETTINGS do not apply to it (a
 * refused DOCTYPE or only ACCESS_EXTERNAL_DTD still lets xs:import and schemaLocation fetch).
 */
export const SCHEMA_SETTINGS = Object.freeze(
  ACCESS_DTD.flatMap((dtd) => ACCESS_SCHEMA.map((schema) => ({
    name: `external DTD and schema access denied (${dtd}, ${schema})`,
    anyOrder: true,
    stmts: [`R.setProperty(${dtd}, "");`, `R.setProperty(${schema}, "");`],
  }))),
);

const permutations = (xs) => (xs.length <= 1 ? [xs] : xs.flatMap((x, i) => permutations([...xs.slice(0, i), ...xs.slice(i + 1)]).map((p) => [x, ...p])));
/** The statement sequences of a row on receiver `r`. */
export const sequences = (row, r) => (row.anyOrder ? permutations(row.stmts) : [row.stmts]).map((s) => s.map((x) => x.replaceAll('R.', `${r}.`)));

const lines = (stmts, pad) => stmts.map((s) => pad + s).join(`\n${pad}...\n`);
/** Where a setting on $F is recognised; `body` is the statement sequence. */
export const POSITIONS = Object.freeze({
  before: (s) => `${lines(s, '')}\n...`,
  'try block before': (s) => `try {\n  ...\n${lines(s, '  ')}\n  ...\n} catch ($EX $E) {\n  ...\n}\n...`,
  'field, static block': (s) => `class $C {\n  ...\n  $FT $F = $INIT;\n  ...\n  static {\n    ...\n${lines(s, '    ')}\n    ...\n  }\n  ...\n}`,
  'field, constructor': (s) => `class $C {\n  ...\n  $FT $F = $INIT;\n  ...\n  $C(...) {\n    ...\n${lines(s, '    ')}\n    ...\n  }\n  ...\n}`,
  'field, method': (s) => `class $C {\n  ...\n  $FT $F = $INIT;\n  ...\n  $RT $M(...) {\n    ...\n${lines(s, '    ')}\n    ...\n  }\n  ...\n}`,
});

const notInside = (body) => `- pattern-not-inside: |\n${body.split('\n').map((l) => (l ? `    ${l}` : l)).join('\n')}\n`;
const indent = (s) => s.split('\n').map((l) => (l ? `      ${l}` : l)).join('\n');

/** The `pattern-not-inside` entries of one block, unindented. */
function exclusions(settings, { secureProcessing, parserForms }) {
  let out = '';
  for (const [where, template] of Object.entries(POSITIONS)) {
    out += `# Set on the factory, reader or builder: ${where}.\n`;
    for (const row of settings) for (const s of sequences(row, '$F')) out += notInside(template(s));
  }
  out += '# Secure processing set explicitly on a built-in JDK factory (newDefaultInstance), which\n# then denies external access.\n';
  for (const make of secureProcessing) {
    for (const fsp of ['javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING', '"http://javax.xml.XMLConstants/feature/secure-processing"']) {
      const set = [`$F.setFeature(${fsp}, true);`];
      out += notInside(`$F = $FACT.${make}();\n...\n${POSITIONS.before(set)}`);
      out += notInside(`$F = $FACT.${make}();\n...\n${POSITIONS['try block before'](set)}`);
    }
  }
  if (parserForms) {
    out += '# Set on the SAXParser, or on its XMLReader, after it was created and before it is used.\n';
    for (const row of settings.filter((r) => r.stmts[0].includes('$SET'))) {
      for (const s of sequences(row, '$P')) out += notInside(`$P = $F.$USE(...);\n...\n${POSITIONS.before(s)}`);
    }
    for (const row of settings.filter((r) => !r.stax)) {
      for (const s of sequences(row, '$R')) out += notInside(`$R = $E.getXMLReader();\n...\n${POSITIONS.before(s)}`);
    }
  }
  return out;
}

const PAD = '          ';
/** The generated blocks of xxe.yml, each between its own markers. */
export const BLOCKS = Object.freeze([
  {
    name: 'parsers, builders, readers and transformers',
    settings: SETTINGS,
    begin: `${PAD}# BEGIN generated by tools/xxe-exclusions.mjs from its SETTINGS table; do not edit by hand.`,
    end: `${PAD}# END generated by tools/xxe-exclusions.mjs from its SETTINGS table`,
    options: { secureProcessing: ['newDefaultInstance', 'newDefaultNSInstance'], parserForms: true },
  },
  {
    name: 'SchemaFactory',
    settings: SCHEMA_SETTINGS,
    begin: `${PAD}# BEGIN generated by tools/xxe-exclusions.mjs from its SCHEMA_SETTINGS table; do not edit by hand.`,
    end: `${PAD}# END generated by tools/xxe-exclusions.mjs from its SCHEMA_SETTINGS table`,
    options: { secureProcessing: ['newDefaultInstance'], parserForms: false },
  },
]);

/** The generated text of `block`, markers included. */
export function generate(block) {
  const body = exclusions(block.settings, block.options)
    .split('\n')
    .map((l) => (l ? `${PAD}${l}` : l))
    .join('\n');
  return `${block.begin}\n${body}${block.end}\n`;
}

/** `text` with the lines from `block.begin` to `block.end` replaced by `generated`. */
export function replaceBlock(text, block, generated) {
  const a = text.indexOf(block.begin);
  const b = text.indexOf(block.end);
  if (a < 0 || b < a || text.indexOf(block.begin, a + 1) >= 0) throw new Error(`${RULE}: markers of the ${block.name} block not found once`);
  return text.slice(0, a) + generated + text.slice(text.indexOf('\n', b) + 1);
}

/** `text` with every block regenerated. */
export const regenerate = (text) => BLOCKS.reduce((t, block) => replaceBlock(t, block, generate(block)), text);

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = readFileSync(RULE, 'utf8');
  const next = regenerate(text);
  if (process.argv.includes('--check')) {
    if (next !== text) {
      console.error('xxe-exclusions: rules/java/xxe/xxe.yml differs from the SETTINGS or SCHEMA_SETTINGS table; run node tools/xxe-exclusions.mjs');
      process.exit(1);
    }
    console.log('xxe-exclusions: ok');
  } else {
    writeFileSync(RULE, next);
  }
}
