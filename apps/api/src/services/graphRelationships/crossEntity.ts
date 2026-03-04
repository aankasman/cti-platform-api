/**
 * Graph Relationships — Cross-Entity Links
 * 
 * IOC ↔ CVE correlations by shared tags/threat types.
 */

import type { RelationshipLink } from './types';

/**
 * Find IOCs and CVEs that share common tags or threat types,
 * creating cross-entity relationship links.
 */
export async function getTagBasedLinks(
    iocNodes: Array<{ id: string; tags?: string[]; threatType?: string }>,
    cveNodes: Array<{ id: string; cveId?: string; severity?: string }>,
): Promise<RelationshipLink[]> {
    const links: RelationshipLink[] = [];
    const seenLinks = new Set<string>();

    // Group IOCs by threat type for CVE matching
    const iocsByThreatType = new Map<string, string[]>();
    for (const ioc of iocNodes) {
        const tt = ioc.threatType?.toLowerCase();
        if (tt && tt !== 'unknown') {
            if (!iocsByThreatType.has(tt)) iocsByThreatType.set(tt, []);
            iocsByThreatType.get(tt)!.push(ioc.id);
        }
    }

    // Link critical/high CVEs to ransomware/malware IOCs
    const ransomwareIOCs = [
        ...(iocsByThreatType.get('ransomware') || []),
        ...(iocsByThreatType.get('malware') || []),
    ].slice(0, 10);

    for (const cve of cveNodes) {
        if (cve.severity === 'critical' || cve.severity === 'high') {
            for (const iocId of ransomwareIOCs.slice(0, 3)) {
                const linkKey = `cve-${cve.id}|${iocId}`;
                if (!seenLinks.has(linkKey)) {
                    seenLinks.add(linkKey);
                    links.push({
                        source: `cve-${cve.id}`,
                        target: iocId.startsWith('ioc-') ? iocId : `ioc-${iocId}`,
                        type: 'threat-correlation',
                        label: 'severity match',
                    });
                }
            }
        }
    }

    return links;
}
