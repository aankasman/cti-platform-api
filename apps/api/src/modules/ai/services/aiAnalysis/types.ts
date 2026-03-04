/**
 * AI Analysis — Type Definitions
 */

export type EntityType = 'ioc' | 'cve' | 'actor';
export type AnalysisType = 'threat-assessment' | 'malware-classification' | 'risk-score' | 'summarization' | 'cve-analysis' | 'actor-profile';


export interface AnalysisRequest {
    iocId: string;
    iocValue: string;
    iocType?: string;
    analysisType: AnalysisType;
    context?: Record<string, unknown>;
}

export interface EntityAnalysisRequest {
    entityId: string;
    entityType: EntityType;
    entityData: Record<string, unknown>;
    forceRefresh?: boolean; // If true, bypass cache and regenerate analysis
}


export interface ThreatAssessment {
    severity: 'low' | 'medium' | 'high' | 'critical';
    confidence: number;
    threatType: string;
    description: string;
    recommendations: string[];
    ttps: string[];
    relatedIndicators: string[];
}

export interface MalwareClassification {
    family: string;
    variant?: string;
    confidence: number;
    behaviors: string[];
    capabilities: string[];
    associatedActors: string[];
}

export interface RiskScoreResult {
    score: number; // 0-100
    factors: Array<{ name: string; impact: number; description: string }>;
    mitigations: string[];
}

export interface CVEAnalysis {
    exploitabilityScore: number; // 0-10
    priorityLevel: 'immediate' | 'high' | 'medium' | 'low' | 'monitor';
    attackVector: string;
    attackComplexity: string;
    impactAnalysis: string;
    affectedSystems: string[];
    remediationSteps: string[];
    workarounds: string[];
    relatedVulnerabilities: string[];
    threatActors: string[];
}

export interface ActorProfile {
    threatLevel: 'critical' | 'high' | 'medium' | 'low';
    operationalSummary: string;
    primaryTargets: string[];
    ttpsUsed: string[];
    knownCampaigns: string[];
    attributionConfidence: number;
    defenseRecommendations: string[];
    indicatorsToWatch: string[];
    relatedActors: string[];
}

export interface EntityAnalysisResult {
    success: boolean;
    entityType: EntityType;
    entityId: string;
    analyzedAt: string;
    data?: ThreatAssessment | MalwareClassification | RiskScoreResult | CVEAnalysis | ActorProfile | string;
    error?: string;
    provider: string;
    tokensUsed?: number;
    cached?: boolean; // True if result was retrieved from cache
}


export interface AnalysisResult {
    success: boolean;
    analysisType: AnalysisType;
    iocId: string;
    iocValue: string;
    analyzedAt: string;
    data?: ThreatAssessment | MalwareClassification | RiskScoreResult | CVEAnalysis | ActorProfile | string;
    error?: string;
    provider: string;
    tokensUsed?: number;
}
