import { db } from '@rinjani/db';
import { threatActors, mitreRelationships } from '@rinjani/db/schema';
import { eq, inArray } from '@rinjani/db';

async function run() {
    const actors = await db.select().from(threatActors).where(eq(threatActors.name, 'APT29'));
    console.log("Actors found:", actors.map(a => ({ id: a.id, stixId: a.stixId, confidence: a.confidence, source: a.createdByRef })));
    const stixIds = actors.map(a => a.stixId);
    if(stixIds.length > 0) {
        const rels = await db.select().from(mitreRelationships).where(inArray(mitreRelationships.sourceId, stixIds));
        console.log("Rels found:", rels.length);
    }
    process.exit(0);
}
run().catch(console.error);
