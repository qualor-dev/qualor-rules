import DOMPurify from 'isomorphic-dompurify';

type Props = { params: Promise<{ slug: string }> };

async function getPage(slug: string): Promise<{ title: string; html: string }> {
  return { title: slug, html: '' };
}

// Next.js App Router page rendering CMS HTML.
export default async function Page({ params }: Props) {
  const { slug } = await params;
  const page = await getPage(slug);
  const jsonLd = { '@context': 'https://schema.org', '@type': 'Article', headline: page.title };
  return (
    <main>
      <div
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: page.html }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(page.html) }}
      />
      <script
        type="application/ld+json"
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, '\\u003c') }}
      />
    </main>
  );
}

// A typed markup object.
export function Notice({ text }: { text: string }) {
  // ruleid: js.react-dangerous-html
  const markup: { __html: string } = { __html: text };
  return <p dangerouslySetInnerHTML={markup} />;
}

// A cast does not change the HTML; sanitised HTML in a variable is fine.
export function Cast({ html }: { html: unknown }) {
  const safe = DOMPurify.sanitize(String(html));
  return (
    <section>
      <div
        // ruleid: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: html as string }}
      />
      <div
        // ok: js.react-dangerous-html
        dangerouslySetInnerHTML={{ __html: safe }}
      />
    </section>
  );
}

// A sanitize() of another object is no HTML sanitiser, also when its result is kept first.
const scrubber = { sanitize: (s: string) => s.trim() };
export function Scrubbed({ text }: { text: string }) {
  const scrubbed = scrubber.sanitize(text);
  // ruleid: js.react-dangerous-html
  return <p dangerouslySetInnerHTML={{ __html: scrubbed }} />;
}

// A sanitize() of another object is no HTML sanitiser.
const cleaner = { sanitize: (s: string) => s.trim() };
export function Untrusted({ text }: { text: string }) {
  // ruleid: js.react-dangerous-html
  return <p dangerouslySetInnerHTML={{ __html: cleaner.sanitize(text) }} />;
}
