/**
 * Tests for the HTML readability shim — Phase 3 #1 follow-on.
 *
 * The PDF + URL fetch paths need real I/O (a PDF buffer, a live server)
 * to exercise meaningfully; both are covered in the PR test plan. The
 * deterministic piece worth pinning is `htmlToReadableText` — what
 * exactly survives the strip-then-flatten pass.
 */
import { describe, it, expect } from 'vitest';
import { htmlToReadableText } from '../services/reportSources';

describe('htmlToReadableText — semantic content extraction', () => {
    it('extracts paragraph + heading text from a vendor-blog-shaped page', () => {
        const html = `
            <html>
                <head><title>APT99 deep dive — 2026 Q2</title></head>
                <body>
                    <nav>Home About Contact</nav>
                    <article>
                        <h1>APT99 deep dive</h1>
                        <p>The actor used 198.51.100.42 as a C2 endpoint.</p>
                        <p>Observed hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</p>
                    </article>
                    <footer>(c) 2026</footer>
                </body>
            </html>`;
        const { text, title } = htmlToReadableText(html);
        expect(title).toBe('APT99 deep dive — 2026 Q2');
        expect(text).toContain('The actor used 198.51.100.42');
        expect(text).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        // Nav + footer dropped
        expect(text).not.toContain('Home About Contact');
        expect(text).not.toContain('(c) 2026');
    });

    it('strips scripts, styles, and SVG so JS code does not bleed in', () => {
        const html = `
            <body>
                <script>var x = '1.2.3.4 not from the article';</script>
                <style>.evil { color: red }</style>
                <svg><text>9.9.9.9 SVG label</text></svg>
                <main>
                    <p>Real article body about 5.6.7.8</p>
                </main>
            </body>`;
        const { text } = htmlToReadableText(html);
        expect(text).toContain('5.6.7.8');
        expect(text).not.toContain('1.2.3.4');
        expect(text).not.toContain('9.9.9.9');
        expect(text).not.toContain('.evil');
    });

    it('prefers <article> over <main> when both are present', () => {
        const html = `
            <body>
                <main>
                    <p>Site-wide intro that is not the article</p>
                </main>
                <article>
                    <p>The real article content</p>
                </article>
            </body>`;
        const { text } = htmlToReadableText(html);
        expect(text).toContain('The real article content');
        expect(text).not.toContain('Site-wide intro');
    });

    it('falls back to body text when no semantic markup matches', () => {
        const html = `<body><div>Just a div wrapper around 10.0.0.1</div></body>`;
        const { text } = htmlToReadableText(html);
        // Body fallback kicks in; the IOC value survives
        expect(text).toContain('10.0.0.1');
    });

    it('returns empty string for a body with only stripped elements', () => {
        const html = `<body><script>var x=1;</script><style>p{}</style></body>`;
        const { text } = htmlToReadableText(html);
        // Even the body fallback should not surface script/style text
        expect(text.trim()).toBe('');
    });

    it('collapses runs of whitespace inside extracted text', () => {
        const html = `<p>The     actor     used     1.2.3.4</p>`;
        const { text } = htmlToReadableText(html);
        expect(text).toContain('The actor used 1.2.3.4');
    });

    it('extracts <li> + <pre> + <blockquote> alongside paragraphs', () => {
        const html = `
            <body>
                <article>
                    <ul>
                        <li>IOC 1.1.1.1</li>
                        <li>IOC 2.2.2.2</li>
                    </ul>
                    <pre>sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</pre>
                    <blockquote>"The attribution is tentative"</blockquote>
                </article>
            </body>`;
        const { text } = htmlToReadableText(html);
        expect(text).toContain('1.1.1.1');
        expect(text).toContain('2.2.2.2');
        expect(text).toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
        expect(text).toContain('attribution');
    });

    it('returns title as undefined when <title> is missing', () => {
        const html = `<body><p>No title here</p></body>`;
        const { title } = htmlToReadableText(html);
        expect(title).toBeUndefined();
    });
});
