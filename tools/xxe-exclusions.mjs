// The safe-setting exclusions of rules/java/xxe/xxe.yml, generated from two tables.
//
//   node tools/xxe-exclusions.mjs           rewrite the blocks between the markers in xxe.yml
//   node tools/xxe-exclusions.mjs --check   exit 1 when a block differs from its table
//
// Each settings row is one way to make a parser safe: a statement on the factory, reader or
// builder ($F), or, for a `together` row, several statements that are each needed. Each statement
// becomes a `pattern-not-inside` for every POSITION: before the use in the same block, in a try
// block before it (with catch clauses, a finally clause or both: the finally template also
// matches catch clauses), and, for a field, in a static block, a constructor or a method of the
// class. A `together` row gets a pattern-either with one branch per statement, so each statement
// must be unconditional on its own. The settings are per factory: SETTINGS hold for the parsers,
// builders, readers and transformers. A SchemaFactory, which reads
// external schemas (xs:import, xs:include, schemaLocation) under ACCESS_EXTERNAL_SCHEMA and
// external DTDs under ACCESS_EXTERNAL_DTD, must meet every one of the SCHEMA_REQUIREMENTS: each is
// one statement, so each must be set unconditionally (a statement inside an if covers only that
// block). A Validator must meet the same SCHEMA_REQUIREMENTS itself, in a block of its own. Each
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
 * Safe settings; R is the receiver. Every row applies to every receiver in every position (a
 * setting a factory does not support would not compile). `stax: true` marks the StAX properties,
 * which are only kept out of the SAXParser and XMLReader blocks. A row with `together: true` is
 * safe only with all of its statements: each one is checked on its own (`parts` names them), so
 * each must be unconditional, and they may be in different places and in any order.
 */
export const SETTINGS = Object.freeze([
  { name: 'DOCTYPE declarations refused', stmts: [`R.setFeature(${DOCTYPE}, true);`] },
  { name: 'DOCTYPE declarations refused (boxed)', stmts: [`R.setFeature(${DOCTYPE}, Boolean.TRUE);`] },
  {
    name: 'external general and parameter entities and the external DTD all off',
    together: true,
    parts: ['external general entities off', 'external parameter entities off', 'the external DTD not loaded'],
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
 * What a SchemaFactory needs: external DTDs and external schemas both denied. Each requirement
 * is met by one statement (the property named by its constant or its name) in one of the five
 * positions; the two may be in different places and in any order. The use is reported when a
 * requirement is unmet: the block is a pattern-either with one branch per requirement. A
 * requirement of two statements in one pattern (`A; ... B; ...`) would let B sit inside an if
 * block, which is why each is a single statement. The rows of SETTINGS do not apply here (a
 * refused DOCTYPE or only ACCESS_EXTERNAL_DTD still lets xs:import and schemaLocation fetch).
 */
export const SCHEMA_REQUIREMENTS = Object.freeze([
  {
    name: 'external DTDs and entity references denied (ACCESS_EXTERNAL_DTD "")',
    rows: ACCESS_DTD.map((key) => ({ stmts: [`R.setProperty(${key}, "");`] })),
  },
  {
    name: 'external schemas denied (ACCESS_EXTERNAL_SCHEMA "")',
    rows: ACCESS_SCHEMA.map((key) => ({ stmts: [`R.setProperty(${key}, "");`] })),
  },
]);

/** The statement sequences of a row on receiver `r`: one per statement of a `together` row. */
export const sequences = (row, r) => (row.together ? row.stmts.map((s) => [s]) : [row.stmts]).map((s) => s.map((x) => x.replaceAll('R.', `${r}.`)));

const lines = (stmts, pad) => stmts.map((s) => pad + s).join(`\n${pad}...\n`);
/** Where a setting on $F is recognised; `s` is the statement sequence. */
export const POSITIONS = Object.freeze({
  before: (s) => `${lines(s, '')}\n...`,
  'try block before': (s) => `try {\n  ...\n${lines(s, '  ')}\n  ...\n} catch ($EX $E) {\n  ...\n}\n...`,
  // A pattern with a finally clause also matches a try statement with catch clauses before it.
  'try block with a finally clause before': (s) => `try {\n  ...\n${lines(s, '  ')}\n  ...\n} finally {\n  ...\n}\n...`,
  'field, static block': (s) => `class $C {\n  ...\n  $FT $F = $INIT;\n  ...\n  static {\n    ...\n${lines(s, '    ')}\n    ...\n  }\n  ...\n}`,
  'field, constructor': (s) => `class $C {\n  ...\n  $FT $F = $INIT;\n  ...\n  $C(...) {\n    ...\n${lines(s, '    ')}\n    ...\n  }\n  ...\n}`,
  'field, method': (s) => `class $C {\n  ...\n  $FT $F = $INIT;\n  ...\n  $RT $M(...) {\n    ...\n${lines(s, '    ')}\n    ...\n  }\n  ...\n}`,
});

/** Shifts every non-empty line of `text` right by `pad`. */
const shift = (text, pad) => text.split('\n').map((l) => (l ? pad + l : l)).join('\n');

const notInside = (body) => `- pattern-not-inside: |\n${body.split('\n').map((l) => (l ? `    ${l}` : l)).join('\n')}\n`;

/** The exclusions for the SAXParser ($P, `$SET` rows) and its XMLReader ($R, all but StAX rows). */
function parserFormExclusions(rows) {
  let out = '';
  for (const row of rows.filter((r) => r.stmts[0].includes('$SET'))) {
    for (const s of sequences(row, '$P')) out += notInside(`$P = $F.$USE(...);\n...\n${POSITIONS.before(s)}`);
  }
  for (const row of rows.filter((r) => !r.stax)) {
    for (const s of sequences(row, '$R')) out += notInside(`$R = $E.getXMLReader();\n...\n${POSITIONS.before(s)}`);
  }
  return out;
}

/**
 * The entries of a `together` row, unindented: a pattern-either with one branch per statement
 * that keeps the use when that statement is not set (on $F in every position, and on the
 * XMLReader of a SAXParser when `parserForms`). In a branch, `$F.$CALL(...)` binds $F as the
 * receiver of the use (the factory, reader or builder); a larger call on the same $F meets the
 * same exclusions; OpenGrep also keeps a use whose range holds such a call (a transformer made
 * and used in place). A transformer kept in a variable is used by a call on the transformer, and
 * a TransformerFactory has none of these SAX features, so a last branch keeps those uses: it binds
 * $F as the transformer's factory, so no other use passes through it.
 */
function togetherExclusions(row, { parserForms, transformers, receiver }) {
  let out = `# Reported unless ${row.name}.\n# One branch per setting, each a single statement, so each must be set unconditionally.\n- pattern-either:\n`;
  row.stmts.forEach((stmt, i) => {
    const one = { name: row.parts[i], stmts: [stmt] };
    let branch = `# Reported unless ${row.parts[i]}.\n- patterns:\n    - pattern: $F.$CALL(...)\n`;
    branch += shift(exclusions([one], { secureProcessing: [], parserForms: false, receiver }), '    ');
    if (parserForms) branch += shift(`# Set on the XMLReader of a SAXParser after it was created.\n${parserFormExclusions([one])}`, '    ');
    out += shift(branch, '    ');
  });
  if (transformers) {
    out += shift('# A transformer kept in a variable (a TransformerFactory has none of these features).\n- pattern-inside: |\n    $TR = $F.newTransformer(...);\n    ...\n', '    ');
  }
  return out;
}

/** The `pattern-not-inside` entries of one block, unindented; `receiver` names $F in the comments. */
function exclusions(allSettings, { secureProcessing, parserForms, transformers, receiver = 'the factory, reader or builder' }) {
  const settings = allSettings.filter((r) => !r.together);
  let out = '';
  for (const [where, template] of Object.entries(POSITIONS)) {
    if (settings.length === 0) break;
    out +=`# Set on ${receiver}: ${where}.\n`;
    for (const row of settings) for (const s of sequences(row, '$F')) out += notInside(template(s));
  }
  if (secureProcessing.length > 0) out += '# Secure processing set explicitly on a built-in JDK factory (newDefaultInstance), which\n# then denies external access.\n';
  for (const make of secureProcessing) {
    for (const fsp of ['javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING', '"http://javax.xml.XMLConstants/feature/secure-processing"']) {
      const set = [`$F.setFeature(${fsp}, true);`];
      // The creation statement anchors the sequence, and `...` reaches a setting nested after it
      // (in a try block too), so the before position is the only one needed.
      out += notInside(`$F = $FACT.${make}();\n...\n${POSITIONS.before(set)}`);
    }
  }
  if (parserForms) {
    out += '# Set on the SAXParser, or on its XMLReader, after it was created and before it is used.\n';
    out += parserFormExclusions(settings);
  }
  for (const row of allSettings.filter((r) => r.together)) out += togetherExclusions(row, { parserForms, transformers, receiver });
  return out;
}

/**
 * The entries of a block with requirements, unindented: secure processing (which meets them all)
 * at the top level, then a pattern-either with one branch per requirement that keeps the use
 * when that requirement is unmet.
 */
function requirementExclusions(requirements, { secureProcessing, use, receiver }) {
  let out = exclusions([], { secureProcessing, parserForms: false });
  out += '- pattern-either:\n';
  for (const req of requirements) {
    let branch = `# Reported unless ${req.name}.\n- patterns:\n    - pattern: ${use}\n`;
    branch += shift(exclusions(req.rows, { secureProcessing: [], parserForms: false, receiver }), '    ');
    out += shift(branch, '    ');
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
    options: { secureProcessing: ['newDefaultInstance', 'newDefaultNSInstance'], parserForms: true, transformers: true },
  },
  {
    name: 'SchemaFactory',
    requirements: SCHEMA_REQUIREMENTS,
    begin: `${PAD}# BEGIN generated by tools/xxe-exclusions.mjs from its SCHEMA_REQUIREMENTS table; do not edit by hand.`,
    end: `${PAD}# END generated by tools/xxe-exclusions.mjs from its SCHEMA_REQUIREMENTS table`,
    options: { secureProcessing: ['newDefaultInstance'], use: '$F.newSchema(...)' },
  },
  {
    // A Validator reads external DTDs and schemaLocation references under the same two
    // properties (Validator.setProperty); secure processing is a factory setting.
    name: 'Validator',
    requirements: SCHEMA_REQUIREMENTS,
    begin: `${PAD}# BEGIN generated by tools/xxe-exclusions.mjs (Validator) from its SCHEMA_REQUIREMENTS table; do not edit by hand.`,
    end: `${PAD}# END generated by tools/xxe-exclusions.mjs (Validator) from its SCHEMA_REQUIREMENTS table`,
    options: { secureProcessing: [], use: '$F.validate(...)', receiver: 'the validator' },
  },
]);

/** The generated text of `block`, markers included. */
export function generate(block) {
  const body = (block.requirements ? requirementExclusions(block.requirements, block.options) : exclusions(block.settings, block.options))
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
      console.error('xxe-exclusions: rules/java/xxe/xxe.yml differs from the SETTINGS or SCHEMA_REQUIREMENTS table; run node tools/xxe-exclusions.mjs');
      process.exit(1);
    }
    console.log('xxe-exclusions: ok');
  } else {
    writeFileSync(RULE, next);
  }
}
