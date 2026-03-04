/**
 * Enrich IOC Fields - Add threat type, severity, and confidence
 * 
 * This script updates existing AlienVault IOCs that are missing 
 * threatType, severity, or confidence by inferring them from pulse data.
 */

import { db } from '@rinjani/db';
import { iocs, pulses } from '@rinjani/db/schema';
import { eq, isNull, and, sql } from '@rinjani/db';

const BATCH_SIZE = 1000;

/**
 * Infer threat type from pulse metadata
 */
function inferThreatType(tags: string[], malwareFamilies: string[], adversary: string | null): string {
    const allTerms = [
        ...tags.map(t => t.toLowerCase()),
        ...malwareFamilies.map(m => m.toLowerCase()),
        adversary?.toLowerCase() || ''
    ];

    // Priority-ordered threat type detection
    if (allTerms.some(t => t.includes('ransomware') || t.includes('ransom'))) return 'ransomware';
    if (allTerms.some(t => t.includes('apt') || t.includes('threat actor') || t.includes('nation-state'))) return 'apt';
    if (allTerms.some(t => t.includes('c2') || t.includes('c&c') || t.includes('command and control') || t.includes('beacon'))) return 'c2';
    if (allTerms.some(t => t.includes('phishing') || t.includes('credential harvesting') || t.includes('spear-phishing'))) return 'phishing';
    if (allTerms.some(t => t.includes('botnet') || t.includes('mirai') || t.includes('emotet'))) return 'botnet';
    if (allTerms.some(t => t.includes('trojan') || t.includes('rat') || t.includes('remote access'))) return 'trojan';
    if (allTerms.some(t => t.includes('stealer') || t.includes('infostealer') || t.includes('keylogger') || t.includes('formgrabber'))) return 'stealer';
    if (allTerms.some(t => t.includes('exploit') || t.includes('vulnerability') || t.includes('cve-') || t.includes('0day') || t.includes('zero-day'))) return 'exploit';
    if (allTerms.some(t => t.includes('miner') || t.includes('cryptominer') || t.includes('cryptojacking') || t.includes('coinhive'))) return 'miner';
    if (allTerms.some(t => t.includes('backdoor') || t.includes('webshell') || t.includes('shell'))) return 'backdoor';
    if (allTerms.some(t => t.includes('dropper') || t.includes('downloader') || t.includes('loader'))) return 'dropper';
    if (allTerms.some(t => t.includes('wiper') || t.includes('destructive'))) return 'wiper';
    if (allTerms.some(t => t.includes('worm') || t.includes('self-propagating'))) return 'worm';
    if (allTerms.some(t => t.includes('spyware') || t.includes('surveillance'))) return 'spyware';
    if (allTerms.some(t => t.includes('adware') || t.includes('pup') || t.includes('potentially unwanted'))) return 'adware';
    if (allTerms.some(t => t.includes('scanner') || t.includes('reconnaissance') || t.includes('port scan'))) return 'scanner';
    if (allTerms.some(t => t.includes('brute') || t.includes('password spray') || t.includes('credential stuffing'))) return 'brute_force';
    if (allTerms.some(t => t.includes('ddos') || t.includes('denial of service') || t.includes('amplification'))) return 'ddos';
    if (allTerms.some(t => t.includes('spam') || t.includes('scam') || t.includes('fraud'))) return 'spam';
    if (allTerms.some(t => t.includes('dns') || t.includes('sinkhole') || t.includes('dga'))) return 'dns_abuse';

    // Malware family present but no specific type matched
    if (malwareFamilies.length > 0) return 'malware';

    return 'unclassified';
}

/**
 * Infer severity from TLP and adversary
 */
function inferSeverity(tlp: string | null, adversary: string | null, tags: string[]): string {
    const tlpLower = (tlp || '').toLowerCase();
    if (tlpLower === 'red') return 'critical';
    if (tlpLower === 'amber') return 'high';
    if (adversary && adversary.length > 0) return 'high';

    const tagsLower = tags.map(t => t.toLowerCase());
    if (tagsLower.some(t => t.includes('critical') || t.includes('ransomware') || t.includes('apt'))) return 'critical';
    if (tagsLower.some(t => t.includes('high') || t.includes('targeted') || t.includes('exploit'))) return 'high';
    if (tagsLower.some(t => t.includes('low') || t.includes('spam'))) return 'low';

    return 'medium';
}

/**
 * Infer confidence from pulse metadata
 */
function inferConfidence(subscriberCount: number, adversary: string | null, indicatorCount: number,
    references: string[], attackIds: string[]): number {
    let confidence = 50;

    if (subscriberCount > 1000) confidence += 25;
    else if (subscriberCount > 100) confidence += 15;
    else if (subscriberCount > 10) confidence += 5;

    if (adversary && adversary.length > 0) confidence += 10;
    if (indicatorCount > 100) confidence += 5;
    if (references && references.length > 0) confidence += 5;
    if (attackIds && attackIds.length > 0) confidence += 5;

    return Math.min(confidence, 95);
}

async function enrichIOCs() {
    console.log('🔧 IOC Enrichment - Adding threat type, severity, and confidence');

    // Get IOCs missing fields grouped by pulseId
    const missingFields = await db.select({
        id: iocs.id,
        pulseId: iocs.pulseId,
    })
        .from(iocs)
        .where(
            and(
                eq(iocs.source, 'alienvault'),
                isNull(iocs.threatType)
            )
        )
        .limit(BATCH_SIZE);

    console.log(`📋 Found ${missingFields.length} IOCs missing fields`);

    if (missingFields.length === 0) {
        console.log('✅ All IOCs have been enriched!');
        return;
    }

    // Get unique pulse IDs
    const pulseIds = [...new Set(missingFields.map(i => i.pulseId).filter(Boolean))];
    console.log(`🔍 Looking up ${pulseIds.length} pulses for metadata...`);

    // Fetch pulse data for enrichment
    const pulseData = new Map<string, {
        tags: string[];
        malwareFamilies: string[];
        adversary: string | null;
        tlp: string | null;
        subscriberCount: number;
        indicatorCount: number;
        references: string[];
        attackIds: string[];
    }>();

    for (const pulseId of pulseIds) {
        if (!pulseId) continue;

        const pulse = await db.select()
            .from(pulses)
            .where(eq(pulses.otxId, pulseId))
            .limit(1);

        if (pulse.length > 0) {
            const p = pulse[0];
            pulseData.set(pulseId, {
                tags: p.tags || [],
                malwareFamilies: p.malwareFamilies || [],
                adversary: p.adversary,
                tlp: p.tlp,
                subscriberCount: p.subscriberCount || 0,
                indicatorCount: p.indicatorCount || 0,
                references: [],
                attackIds: p.attackIds || [],
            });
        }
    }

    console.log(`📊 Found pulse data for ${pulseData.size} pulses`);

    // Update IOCs in batch
    let updated = 0;
    for (const ioc of missingFields) {
        const pulse = ioc.pulseId ? pulseData.get(ioc.pulseId) : null;

        if (pulse) {
            const threatType = inferThreatType(pulse.tags, pulse.malwareFamilies, pulse.adversary);
            const severity = inferSeverity(pulse.tlp, pulse.adversary, pulse.tags);
            const confidence = inferConfidence(
                pulse.subscriberCount,
                pulse.adversary,
                pulse.indicatorCount,
                pulse.references,
                pulse.attackIds
            );

            await db.update(iocs)
                .set({
                    threatType,
                    severity,
                    confidence,
                    updatedAt: new Date(),
                })
                .where(eq(iocs.id, ioc.id));

            updated++;
        } else {
            // No pulse data - set defaults
            await db.update(iocs)
                .set({
                    threatType: 'unclassified',
                    severity: 'medium',
                    confidence: 50,
                    updatedAt: new Date(),
                })
                .where(eq(iocs.id, ioc.id));

            updated++;
        }
    }

    console.log(`✅ Enriched ${updated} IOCs`);
}

// Run
enrichIOCs()
    .then(() => {
        console.log('✅ IOC enrichment complete!');
        process.exit(0);
    })
    .catch(error => {
        console.error('❌ Enrichment failed:', error);
        process.exit(1);
    });
