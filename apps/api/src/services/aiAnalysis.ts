/**
 * AI Analysis Service — Barrel Re-export
 *
 * Provides AI-powered threat analysis capabilities for:
 * - IOCs (Indicators of Compromise)
 * - CVEs (Common Vulnerabilities and Exposures)
 * - Threat Actors
 *
 * Supports multiple analysis types and AI providers.
 * Results are cached in the database for instant retrieval.
 */

// Types
export type {
    EntityType, AnalysisType, AnalysisRequest, EntityAnalysisRequest,
    ThreatAssessment, MalwareClassification, RiskScoreResult, CVEAnalysis, ActorProfile,
    EntityAnalysisResult, AnalysisResult,
} from './aiAnalysis/types';

// Core analysis functions
export { analyzeIOC, analyzeEntity } from './aiAnalysis/analysis';
