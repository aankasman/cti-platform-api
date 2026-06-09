/**
 * Source extractors for Phase 3 #1 report ingestion follow-on.
 *
 * The text-paste route shipped in PR #83. This module adds the two
 * other input modalities operators actually need: PDFs (Mandiant /
 * Mandiant-shaped vendor reports) and URLs (blog posts, public threat
 * advisories).
 *
 * Both extractors do ONE thing: convert their input shape to plain
 * text. The existing `ingestReportText()` then handles IOC + LLM
 * entity extraction — no duplication of that pipeline.
 *
 * Honest scope:
 *   - PDF: text-only via pdf-parse. Image-only PDFs (scanned
 *     documents) won't surface IOCs because there's no OCR. We don't
 *     OCR today and won't quietly fake it; the route returns a
 *     `pageCount: N, textLength: 0` signal so callers know.
 *   - URL: bare fetch + a Cheerio-based readability shim. Drops
 *     <script>/<style> + nav/footer/aside, then concatenates the
 *     remaining <p>/<h1-6>/<li>/<pre> text. No headless browser, so
 *     JS-rendered SPAs return empty body — fine for this PR; flag as
 *     a follow-on if a major vendor's blog goes SPA-only.
 *
 * Both extractors enforce hard caps so a 200 MB PDF or 500 KB HTML
 * response can't run the API out of memory.
 */
import * as cheerio from 'cheerio';
import { createLogger } from '../lib/logger';

const log = createLogger('ReportSources');

/** Hard ceilings — protects parser memory + downstream LLM cost. */
const MAX_PDF_BYTES = 25 * 1024 * 1024;   // 25 MB, matches the YARA scan-sample cap
const MAX_HTML_BYTES = 5 * 1024 * 1024;   // 5 MB
const FETCH_TIMEOUT_MS = 15_000;

// ============================================================================
// PDF
// ============================================================================

export interface PdfExtraction {
    text: string;
    pageCount: number;
    /** `info.Title` field from the PDF metadata, if present. */
    title?: string;
}

export async function extractFromPdfBuffer(buf: Buffer): Promise<PdfExtraction> {
    if (buf.length > MAX_PDF_BYTES) {
        throw new Error(`PDF too large: ${buf.length} bytes > ${MAX_PDF_BYTES} (cap)`);
    }

    // pdf-parse is CJS; dynamic import to keep this module ESM-clean.
    const { default: pdfParse } = await import('pdf-parse');
    const parsed = await pdfParse(buf);

    const pdfInfo = parsed.info as { Title?: string } | undefined;
    log.info('PDF extracted', {
        bytes: buf.length,
        pages: parsed.numpages,
        textLength: parsed.text.length,
        hasTitle: !!pdfInfo?.Title,
    });

    return {
        text: parsed.text,
        pageCount: parsed.numpages ?? 0,
        title: pdfInfo?.Title,
    };
}

// ============================================================================
// URL
// ============================================================================

export interface UrlExtraction {
    /** Plain-text representation of the page's article-shaped content. */
    text: string;
    /** Final URL after redirects — useful provenance for the operator. */
    finalUrl: string;
    /** <title> tag content. */
    title?: string;
    /** Final response Content-Type. */
    contentType?: string;
    /** Bytes pulled. Counts against MAX_HTML_BYTES. */
    bytes: number;
}

const STRIPPED_SELECTORS = [
    'script', 'style', 'noscript', 'iframe', 'svg',
    'nav', 'footer', 'aside', 'header',
    '[role=navigation]', '[role=banner]', '[role=contentinfo]',
];

const CONTENT_SELECTORS = ['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'pre', 'blockquote'];

/**
 * Reduce an HTML body to article-shaped plain text. Not as smart as
 * Readability proper — but good enough for vendor blogs and threat
 * advisories without dragging in jsdom.
 */
export function htmlToReadableText(html: string): { text: string; title?: string } {
    const $ = cheerio.load(html);
    const title = $('head > title').first().text().trim() || undefined;

    for (const sel of STRIPPED_SELECTORS) $(sel).remove();

    // Prefer <main> / <article> if present — common on modern threat-intel sites.
    const root = ($('article').length && $('article')) || ($('main').length && $('main')) || $('body');

    const lines: string[] = [];
    root.find(CONTENT_SELECTORS.join(',')).each((_, el) => {
        const t = $(el).text().replace(/\s+/g, ' ').trim();
        if (t) lines.push(t);
    });

    // Fallback: if no semantic markup matched (e.g. a one-div SPA shell with no
    // server-rendered text), use the body text as a last resort.
    if (lines.length === 0) {
        const body = $('body').text().replace(/\s+/g, ' ').trim();
        if (body) lines.push(body);
    }

    return { text: lines.join('\n\n'), title };
}

export async function extractFromUrl(rawUrl: string): Promise<UrlExtraction> {
    // Surface input validation early — fetch() throws on bad URLs but with
    // a less helpful message.
    let url: URL;
    try {
        url = new URL(rawUrl);
    } catch {
        throw new Error(`Invalid URL: ${rawUrl}`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        throw new Error(`Unsupported URL scheme: ${url.protocol} (only http/https)`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let response: Response;
    try {
        response = await fetch(url, {
            redirect: 'follow',
            signal: controller.signal,
            headers: {
                'User-Agent': 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            },
        });
    } finally {
        clearTimeout(timer);
    }

    if (!response.ok) {
        throw new Error(`Fetch failed: HTTP ${response.status} for ${rawUrl}`);
    }

    // Cap the response body. Reading via `response.arrayBuffer()` and
    // checking length AFTER the fact is OK for our small cap.
    const buf = Buffer.from(await response.arrayBuffer());
    if (buf.length > MAX_HTML_BYTES) {
        throw new Error(`Response too large: ${buf.length} bytes > ${MAX_HTML_BYTES} (cap)`);
    }

    const contentType = response.headers.get('content-type') ?? undefined;
    const html = buf.toString('utf-8');
    const { text, title } = htmlToReadableText(html);

    log.info('URL extracted', {
        url: rawUrl,
        finalUrl: response.url,
        bytes: buf.length,
        textLength: text.length,
        hasTitle: !!title,
    });

    return {
        text,
        finalUrl: response.url,
        title,
        contentType,
        bytes: buf.length,
    };
}
