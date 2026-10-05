import React from 'react';
import DOMPurify from 'dompurify';
import sanitizeHtml from 'sanitize-html';
import { marked } from 'marked';
import createDOMPurify from 'dompurify';
import { LEGAL_HTML } from './legal';

const FOOTER_HTML = '<p>&copy; Example Ltd</p>';

// Raw HTML from props, state or fetched data: a person should check where it comes from.
// (Annotations sit between the attributes: JSX children cannot hold line comments.)
export function Post({ post, html }) {
  return (
    <article>
      <div
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: post.body }}
      />
      <section
        className="intro"
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: html }}
      ></section>
      <p
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: `<b>${post.title}</b>` }}
      />
      <div
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: marked.parse(post.markdown) }}
      />
      <div
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: marked(post.markdown) }}
      />
    </article>
  );
}

// The markup object made first, as the React documentation recommends.
export function Comment({ comment }) {
  // ruleid: js.react-dangerous-html
  const markup = { __html: comment.text };
  return <div dangerouslySetInnerHTML={markup} />;
}

function renderMarkdown(source) {
  // ruleid: js.react-dangerous-html
  return { __html: marked.parse(source) };
}

export function Preview({ source }) {
  return <div dangerouslySetInnerHTML={renderMarkdown(source)} />;
}

// React.createElement with the prop in an object.
export function Raw({ content }) {
  // ruleid: js.react-dangerous-html
  return React.createElement('div', { dangerouslySetInnerHTML: { __html: content } });
}

// Constants, sanitised HTML and escaped JSON are fine.
export function Safe({ html, data }) {
  const banner = { __html: '<strong>Welcome</strong>' };
  return (
    <div>
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: '<hr />' }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: FOOTER_HTML }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: `<em>static</em>` }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={banner}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: sanitizeHtml(html, { allowedTags: ['b', 'i'] }) }}
      />
      <script
        type="application/ld+json"
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\\u003c') }}
      />
      <div>
        {/* Text as children is escaped by React. */}
        {html}
      </div>
    </div>
  );
}

// HTML sanitised into a variable first, as the sanitize-html README shows.
export function Cleaned({ html }) {
  const clean = sanitizeHtml(html);
  const purified = DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
  return (
    <div>
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: clean }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: purified }}
      />
      <div
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  );
}

// Sanitised HTML that is later joined with raw HTML is still taken for sanitised.
export function Joined({ html, extra }) {
  let clean = sanitizeHtml(html);
  clean = clean + extra;
  return (
    <div
      // todoruleid: js.react-dangerous-html
      dangerouslySetInnerHTML={{ __html: clean }}
    />
  );
}

// JSON without the replacement of '<' can close the script element.
export function Schema({ product }) {
  return (
    <script
      type="application/ld+json"
      // ruleid: js.react-dangerous-html
      dangerouslySetInnerHTML={{ __html: JSON.stringify(product) }}
    />
  );
}

// Look-alikes: other objects with an html key, other props.
export function Other({ html }) {
  // ok: js.react-dangerous-html
  const options = { html: html, sanitize: false };
  // ok: js.react-dangerous-html
  const editor = { innerHTML: html };
  // ok: js.react-dangerous-html
  return <Editor value={html} options={options} config={editor} />;
}

// A DOMPurify instance and constants of other modules are not recognised.
const purify = createDOMPurify(window);
export function Legal({ html }) {
  return (
    <footer>
      <div
        // todook: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: purify.sanitize(html) }}
      />
      <div
        // todook: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: LEGAL_HTML }}
      />
    </footer>
  );
}

// A markup object made in another module (or passed in props) is not followed to the prop.
export function FromProps({ markup }) {
  // todoruleid: js.react-dangerous-html
  return <div dangerouslySetInnerHTML={markup} />;
}

function Editor() {
  return null;
}
