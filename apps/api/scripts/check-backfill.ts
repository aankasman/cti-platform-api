/**
 * Quick diagnostic: check web_intel_items state for backfill readiness.
 */
import { db, sql } from '@rinjani/db';

async function main() {
    console.log('=== Web Intel Items Diagnostic ===\n');

    // 1. Total items
    const total = await db.execute(sql`SELECT COUNT(*) as cnt FROM web_intel_items`);
    const rows = Array.isArray(total) ? total : (total as { rows?: unknown[] }).rows || [];
    console.log('Total items:', rows);

    // 2. Items with text_content
    const withText = await db.execute(
        sql`SELECT COUNT(*) as cnt FROM web_intel_items WHERE text_content IS NOT NULL AND text_content != ''`
    );
    const withTextRows = Array.isArray(withText) ? withText : (withText as { rows?: unknown[] }).rows || [];
    console.log('With text_content:', withTextRows);

    // 3. Sample item
    const sample = await db.execute(
        sql`SELECT id, title, LENGTH(text_content) as text_len, ioc_extracted, source_provider, category 
            FROM web_intel_items 
            WHERE text_content IS NOT NULL AND text_content != '' 
            LIMIT 3`
    );
    const sampleRows = Array.isArray(sample) ? sample : (sample as { rows?: unknown[] }).rows || [];
    console.log('Sample items:', JSON.stringify(sampleRows, null, 2));

    // 4. Check if web_intel_mentions table exists and has data
    const mentions = await db.execute(sql`SELECT COUNT(*) as cnt FROM web_intel_mentions`);
    const mentionRows = Array.isArray(mentions) ? mentions : (mentions as { rows?: unknown[] }).rows || [];
    console.log('Existing mentions:', mentionRows);

    // 5. Check already-extracted items
    const extracted = await db.execute(
        sql`SELECT COUNT(*) as cnt FROM web_intel_items WHERE ioc_extracted = true`
    );
    const extractedRows = Array.isArray(extracted) ? extracted : (extracted as { rows?: unknown[] }).rows || [];
    console.log('Already IOC-extracted:', extractedRows);

    // 6. Result structure from raw execute
    const rawResult = await db.execute(sql`SELECT 1 as test_col`);
    console.log('\nRaw execute result type:', typeof rawResult);
    console.log('Is array?', Array.isArray(rawResult));
    console.log('Keys:', Object.keys(rawResult));
    if (!Array.isArray(rawResult) && typeof rawResult === 'object') {
        console.log('Has .rows?', 'rows' in rawResult);
        console.log('.rows value:', (rawResult as Record<string, unknown>).rows);
    }

    process.exit(0);
}

main().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
