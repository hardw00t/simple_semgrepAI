import { FieldGroup } from './FieldGroup'

// Strip markdown bold formatting from AI-generated text
const stripMarkdown = (text: string) => text.replace(/\*\*/g, '')

interface ImpactGridProps {
  impactAssessment: Record<string, string> | null
  vulnerabilityCategory: Record<string, string> | null
  technicalDetails: Record<string, string> | null
  defaultOpen?: boolean
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function getSeverityColor(value: string): string {
  const v = value.toLowerCase()
  if (v === 'critical') return 'bg-red-600 text-white'
  if (v === 'high') return 'bg-orange-500 text-white'
  if (v === 'medium') return 'bg-yellow-500 text-black'
  if (v === 'low') return 'bg-green-600 text-white'
  return 'bg-muted'
}

function GridItem({
  label,
  value,
  showSeverityColor = false,
}: {
  label: string
  value: string
  showSeverityColor?: boolean
}) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-muted-foreground font-medium">{label}</span>
      <span
        className={`text-sm px-2 py-1 rounded ${
          showSeverityColor ? getSeverityColor(stripMarkdown(value)) : 'bg-muted'
        }`}
      >
        {stripMarkdown(value)}
      </span>
    </div>
  )
}

export function ImpactGrid({
  impactAssessment,
  vulnerabilityCategory,
  technicalDetails,
  defaultOpen = false,
}: ImpactGridProps) {
  const hasImpact = impactAssessment && Object.keys(impactAssessment).length > 0
  const hasVulnerability =
    vulnerabilityCategory && Object.keys(vulnerabilityCategory).length > 0
  const hasTechnical =
    technicalDetails && Object.keys(technicalDetails).length > 0

  if (!hasImpact && !hasVulnerability && !hasTechnical) {
    return null
  }

  return (
    <FieldGroup title="Analysis Details" defaultOpen={defaultOpen}>
      <div className="space-y-4">
        {/* Impact Assessment */}
        {hasImpact && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">
              Impact Assessment
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {Object.entries(impactAssessment!).map(([key, value]) => (
                <GridItem
                  key={key}
                  label={formatLabel(key)}
                  value={value}
                  showSeverityColor
                />
              ))}
            </div>
          </div>
        )}

        {/* Vulnerability Category */}
        {hasVulnerability && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">
              Vulnerability Classification
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {Object.entries(vulnerabilityCategory!).map(([key, value]) => (
                <GridItem key={key} label={formatLabel(key)} value={value} />
              ))}
            </div>
          </div>
        )}

        {/* Technical Details */}
        {hasTechnical && (
          <div>
            <h5 className="text-xs font-medium text-muted-foreground mb-2 uppercase tracking-wide">
              Technical Details
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {Object.entries(technicalDetails!).map(([key, value]) => (
                <GridItem key={key} label={formatLabel(key)} value={value} />
              ))}
            </div>
          </div>
        )}
      </div>
    </FieldGroup>
  )
}
