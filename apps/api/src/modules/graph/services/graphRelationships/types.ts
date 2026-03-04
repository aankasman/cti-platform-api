/**
 * Graph Relationships — Types
 */

export interface RelationshipLink {
    source: string;
    target: string;
    type: string;
    label?: string;
    confidence?: number;
}

export interface RelationshipNode {
    id: string;
    label: string;
    type: 'actor' | 'technique' | 'malware' | 'ioc' | 'cve' | 'pulse';
    subType?: string;
    severity?: string | null;
    source?: string;
}
