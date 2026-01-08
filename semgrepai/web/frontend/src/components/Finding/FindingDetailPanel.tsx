import { useFinding } from '../../hooks/useFindings'
import { AIValidationSection } from './AIValidationSection'
import { CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react'

// Strip markdown bold formatting from AI-generated text
const stripMarkdown = (text: string) => text.replace(/\*\*/g, '')

interface FindingDetailPanelProps {
  scanId: string
  findingId: string
}

function VerdictBadge({ verdict }: { verdict: string | null }) {
  if (!verdict) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-gray-500 text-white">
        <Clock className="h-3 w-3" />
        Unknown
      </span>
    )
  }

  const v = verdict.toLowerCase()
  if (v.includes('true positive')) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-red-600 text-white">
        <XCircle className="h-3 w-3" />
        True Positive
      </span>
    )
  }
  if (v.includes('false positive')) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-green-600 text-white">
        <CheckCircle className="h-3 w-3" />
        False Positive
      </span>
    )
  }
  if (v.includes('needs review')) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-yellow-500 text-black">
        <Clock className="h-3 w-3" />
        Needs Review
      </span>
    )
  }
  if (v.includes('error')) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-gray-500 text-white">
        <AlertTriangle className="h-3 w-3" />
        Error
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-gray-500 text-white">
      {stripMarkdown(verdict)}
    </span>
  )
}

function ConfidenceBadge({ confidence }: { confidence: number | null }) {
  if (confidence === null) return null

  let label: string
  let colorClass: string

  if (confidence >= 0.7) {
    label = 'High Confidence'
    colorClass = 'bg-red-500 text-white'
  } else if (confidence >= 0.4) {
    label = 'Medium Confidence'
    colorClass = 'bg-yellow-500 text-black'
  } else {
    label = 'Low Confidence'
    colorClass = 'bg-green-500 text-white'
  }

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colorClass}`}>
      {label} ({Math.round(confidence * 100)}%)
    </span>
  )
}

function RiskScoreBadge({ score }: { score: number | null }) {
  if (score === null) return null

  let colorClass: string
  if (score >= 8) {
    colorClass = 'bg-red-600 text-white'
  } else if (score >= 5) {
    colorClass = 'bg-orange-500 text-white'
  } else if (score >= 3) {
    colorClass = 'bg-yellow-500 text-black'
  } else {
    colorClass = 'bg-green-600 text-white'
  }

  return (
    <span className={`px-2 py-1 rounded text-xs font-medium ${colorClass}`}>
      Risk: {score}/10
    </span>
  )
}

export function FindingDetailPanel({
  scanId,
  findingId,
}: FindingDetailPanelProps) {
  const { data: finding, isLoading, error } = useFinding(scanId, findingId)

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  if (error || !finding) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-yellow-500" />
        <p>Failed to load finding details</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header with badges */}
      <div className="flex flex-wrap items-center gap-2">
        <VerdictBadge verdict={finding.verdict} />
        <ConfidenceBadge confidence={finding.confidence} />
        <RiskScoreBadge score={finding.risk_score} />
        {finding.processing_time && (
          <span className="text-xs text-muted-foreground">
            Analyzed in {finding.processing_time.toFixed(1)}s
          </span>
        )}
      </div>

      {/* Basic info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
        <div>
          <span className="font-medium">Message:</span>
          <p className="text-muted-foreground mt-1">{finding.message}</p>
        </div>
        <div>
          <span className="font-medium">Location:</span>
          <p className="font-mono text-muted-foreground mt-1">
            {finding.path}:{finding.line}
          </p>
        </div>
      </div>

      {/* AI Validation Results */}
      <AIValidationSection finding={finding} />
    </div>
  )
}
