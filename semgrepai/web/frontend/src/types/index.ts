// Scan types
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface Scan {
  id: string
  name: string | null
  target_path: string
  rules_path: string | null
  status: ScanStatus
  started_at: string | null
  completed_at: string | null
  total_findings: number
  validated_findings: number
  created_at: string
  updated_at: string
  progress_percentage: number
  duration_seconds: number | null
  error_message?: string
}

export interface ScanDetail extends Scan {
  config_snapshot: Record<string, unknown> | null
  true_positives: number
  false_positives: number
  needs_review: number
  severity_critical: number
  severity_high: number
  severity_medium: number
  severity_low: number
}

export interface ScanCreate {
  target_path: string
  rules_path?: string
  name?: string
}

// Finding types
export type TriageStatus = 'needs_review' | 'true_positive' | 'false_positive' | 'accepted_risk' | 'fixed'

export interface Finding {
  id: string
  scan_id: string
  rule_id: string
  severity: string
  message: string | null
  path: string
  line: number
  verdict: string | null
  confidence: number | null
  risk_score: number | null
  triage_status: TriageStatus
  assignee: string | null
  created_at: string
}

export interface FindingDetail extends Finding {
  code: string | null
  justification: string | null
  poc: string | null
  attack_vectors: string[] | null
  trigger_steps: string[] | null
  recommended_fixes: string[] | null
  impact_assessment: Record<string, string> | null
  vulnerability_category: Record<string, string> | null
  technical_details: Record<string, string> | null
  metadata: Record<string, unknown> | null
  triage_note: string | null
  triage_updated_at: string | null
  triage_updated_by: string | null
  processing_time: number | null
  updated_at: string
}

export interface FindingUpdate {
  triage_status?: TriageStatus
  triage_note?: string
  assignee?: string
}

// Stats types
export interface SeverityDistribution {
  critical: number
  high: number
  medium: number
  low: number
  info: number
  unknown: number
}

export interface TriageDistribution {
  needs_review: number
  true_positive: number
  false_positive: number
  accepted_risk: number
  fixed: number
}

export interface VerdictDistribution {
  true_positive: number
  false_positive: number
  needs_review: number
  error: number
}

export interface Stats {
  total_scans: number
  total_findings: number
  pending_scans: number
  running_scans: number
  completed_scans: number
  failed_scans: number
  severity_distribution: SeverityDistribution
  triage_distribution: TriageDistribution
  verdict_distribution: VerdictDistribution
  average_risk_score: number
  critical_findings_count: number
  recent_scans_count: number
  findings_needing_review: number
}

// Pagination types
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// WebSocket types
export interface WebSocketMessage {
  type: 'progress' | 'complete' | 'error' | 'connected' | 'ping' | 'pong' | 'finding_validated'
  scan_id: string
  data?: {
    validated_findings?: number
    total_findings?: number
    finding_id?: string
    [key: string]: unknown
  }
  message?: string
  timestamp: string
}
