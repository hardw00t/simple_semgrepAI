import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useScan, useCancelScan } from '../hooks/useScans'
import { useFindings, useUpdateFinding } from '../hooks/useFindings'
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import type { Finding, TriageStatus } from '../types'
import { FindingDetailPanel } from '../components/Finding'

// Strip markdown bold formatting from AI-generated text
const stripMarkdown = (text: string) => text.replace(/\*\*/g, '')

function SeverityBadge({ severity }: { severity: string }) {
  // Normalize semgrep severities to standard labels
  const normalizedSeverity: Record<string, string> = {
    ERROR: 'HIGH',
    WARNING: 'MEDIUM',
    INFO: 'LOW',
  }
  const displaySeverity = normalizedSeverity[severity.toUpperCase()] || severity.toUpperCase()

  const colors: Record<string, string> = {
    CRITICAL: 'severity-critical',
    HIGH: 'severity-high',
    MEDIUM: 'severity-medium',
    LOW: 'severity-low',
  }

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colors[displaySeverity] || 'bg-gray-500 text-white'}`}>
      {displaySeverity}
    </span>
  )
}

function TriageStatusSelect({
  value,
  onChange,
  disabled,
}: {
  value: TriageStatus
  onChange: (status: TriageStatus) => void
  disabled?: boolean
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as TriageStatus)}
      disabled={disabled}
      className="px-2 py-1 text-sm border rounded-md bg-background"
    >
      <option value="needs_review">Needs Review</option>
      <option value="true_positive">True Positive</option>
      <option value="false_positive">False Positive</option>
      <option value="accepted_risk">Accepted Risk</option>
      <option value="fixed">Fixed</option>
    </select>
  )
}

function FindingRow({
  finding,
  scanId,
  isExpanded,
  onToggle,
  onTriageChange,
  isUpdating,
}: {
  finding: Finding
  scanId: string
  isExpanded: boolean
  onToggle: () => void
  onTriageChange: (status: TriageStatus) => void
  isUpdating: boolean
}) {
  return (
    <>
      <tr
        className="border-b hover:bg-muted/50 cursor-pointer"
        onClick={onToggle}
      >
        <td className="px-4 py-3">
          <button className="p-1">
            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        </td>
        <td className="px-4 py-3">
          <SeverityBadge severity={finding.severity} />
        </td>
        <td className="px-4 py-3 font-mono text-sm">{finding.rule_id}</td>
        <td className="px-4 py-3 text-sm max-w-xs truncate" title={finding.path}>
          {finding.path}:{finding.line}
        </td>
        <td className="px-4 py-3 text-sm">{finding.risk_score ?? '-'}</td>
        <td className="px-4 py-3">
          {finding.verdict ? (
            <span
              className={`inline-flex items-center gap-1 text-sm ${
                finding.verdict.toLowerCase().includes('true positive')
                  ? 'text-red-600'
                  : finding.verdict.toLowerCase().includes('false positive')
                  ? 'text-green-600'
                  : 'text-yellow-600'
              }`}
            >
              {finding.verdict.toLowerCase().includes('true positive') && <XCircle className="h-4 w-4" />}
              {finding.verdict.toLowerCase().includes('false positive') && <CheckCircle className="h-4 w-4" />}
              {!finding.verdict.toLowerCase().includes('positive') && <Clock className="h-4 w-4" />}
              {stripMarkdown(finding.verdict)}
            </span>
          ) : (
            <span className="text-muted-foreground">-</span>
          )}
        </td>
        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
          <TriageStatusSelect
            value={finding.triage_status}
            onChange={onTriageChange}
            disabled={isUpdating}
          />
        </td>
      </tr>
      {isExpanded && (
        <tr className="bg-muted/30">
          <td colSpan={7} className="px-8 py-6">
            <FindingDetailPanel scanId={scanId} findingId={finding.id} />
          </td>
        </tr>
      )}
    </>
  )
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const { data: scan, isLoading: scanLoading } = useScan(scanId!)
  const { data: findings, isLoading: findingsLoading } = useFindings(scanId!, { pageSize: 100 })
  const cancelScan = useCancelScan()
  const updateFinding = useUpdateFinding(scanId!)

  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set())
  const [filters, setFilters] = useState({
    severity: '',
    triageStatus: '',
  })

  if (scanLoading || findingsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold mb-2">Scan not found</h2>
        <Link to="/scans" className="text-primary hover:underline">
          Back to scans
        </Link>
      </div>
    )
  }

  const toggleFinding = (findingId: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev)
      if (next.has(findingId)) {
        next.delete(findingId)
      } else {
        next.add(findingId)
      }
      return next
    })
  }

  const handleTriageChange = (findingId: string, status: TriageStatus) => {
    updateFinding.mutate({ findingId, update: { triage_status: status } })
  }

  // Map standardized severity labels to semgrep native severities
  const severityMap: Record<string, string[]> = {
    CRITICAL: ['CRITICAL'],
    HIGH: ['HIGH', 'ERROR'],      // ERROR maps to High
    MEDIUM: ['MEDIUM', 'WARNING'], // WARNING maps to Medium
    LOW: ['LOW', 'INFO'],          // INFO maps to Low
  }

  const filteredFindings = findings?.items.filter((f) => {
    if (filters.severity) {
      const validSeverities = severityMap[filters.severity] || [filters.severity]
      if (!validSeverities.includes(f.severity.toUpperCase())) return false
    }
    if (filters.triageStatus && f.triage_status !== filters.triageStatus) return false
    return true
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link to="/scans" className="p-2 hover:bg-muted rounded-md flex-shrink-0">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div className="flex-1 min-w-0">
          <h1 className="text-2xl font-bold break-words">{scan.name || 'Unnamed Scan'}</h1>
          <p className="text-muted-foreground truncate" title={scan.target_path}>{scan.target_path}</p>
        </div>
        {scan.status === 'running' && (
          <button
            onClick={() => cancelScan.mutate(scanId!)}
            className="px-4 py-2 text-sm border border-destructive text-destructive rounded-md hover:bg-destructive/10"
          >
            Cancel Scan
          </button>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Status</p>
          <p className="text-lg font-semibold capitalize">{scan.status}</p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">Total Findings</p>
          <p className="text-lg font-semibold">{scan.total_findings}</p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">True Positives</p>
          <p className="text-lg font-semibold text-red-600">{scan.true_positives}</p>
        </div>
        <div className="bg-card rounded-lg p-4 border">
          <p className="text-sm text-muted-foreground">False Positives</p>
          <p className="text-lg font-semibold text-green-600">{scan.false_positives}</p>
        </div>
      </div>

      {/* Progress bar for running scans */}
      {scan.status === 'running' && (
        <div className="bg-card rounded-lg p-4 border">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium">Validation Progress</span>
            <span className="text-sm text-muted-foreground">
              {scan.validated_findings} / {scan.total_findings}
            </span>
          </div>
          <div className="h-2 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${scan.progress_percentage}%` }}
            />
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-2 sm:gap-4">
        <select
          value={filters.severity}
          onChange={(e) => setFilters((f) => ({ ...f, severity: e.target.value }))}
          className="w-full sm:w-auto px-3 py-2 border rounded-md bg-background"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={filters.triageStatus}
          onChange={(e) => setFilters((f) => ({ ...f, triageStatus: e.target.value }))}
          className="w-full sm:w-auto px-3 py-2 border rounded-md bg-background"
        >
          <option value="">All Triage Status</option>
          <option value="needs_review">Needs Review</option>
          <option value="true_positive">True Positive</option>
          <option value="false_positive">False Positive</option>
          <option value="accepted_risk">Accepted Risk</option>
          <option value="fixed">Fixed</option>
        </select>
      </div>

      {/* Findings Table */}
      <div className="bg-card rounded-lg border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px]">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="px-4 py-3 text-left w-10"></th>
                <th className="px-4 py-3 text-left text-sm font-medium min-w-[100px]">Severity</th>
                <th className="px-4 py-3 text-left text-sm font-medium min-w-[200px]">Rule</th>
                <th className="px-4 py-3 text-left text-sm font-medium min-w-[200px]">Location</th>
                <th className="px-4 py-3 text-left text-sm font-medium min-w-[60px]">Risk</th>
                <th className="px-4 py-3 text-left text-sm font-medium min-w-[120px]">AI Verdict</th>
                <th className="px-4 py-3 text-left text-sm font-medium min-w-[140px]">Triage</th>
              </tr>
            </thead>
          <tbody>
            {filteredFindings?.map((finding) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                scanId={scanId!}
                isExpanded={expandedFindings.has(finding.id)}
                onToggle={() => toggleFinding(finding.id)}
                onTriageChange={(status) => handleTriageChange(finding.id, status)}
                isUpdating={updateFinding.isPending}
              />
            ))}
            </tbody>
          </table>
        </div>
        {filteredFindings?.length === 0 && (
          <div className="text-center py-12 text-muted-foreground">
            No findings match the current filters
          </div>
        )}
      </div>
    </div>
  )
}
