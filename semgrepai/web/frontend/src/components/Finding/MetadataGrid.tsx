import { FieldGroup } from './FieldGroup'

interface MetadataGridProps {
  metadata: Record<string, unknown> | null
  defaultOpen?: boolean
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '-'
  }
  if (Array.isArray(value)) {
    return value.join(', ')
  }
  if (typeof value === 'object') {
    return JSON.stringify(value)
  }
  return String(value)
}

function formatLabel(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export function MetadataGrid({ metadata, defaultOpen = false }: MetadataGridProps) {
  if (!metadata || Object.keys(metadata).length === 0) {
    return null
  }

  // Priority fields to show first
  const priorityFields = ['cwe', 'owasp', 'category', 'confidence', 'vulnerability_class']
  const sortedEntries = Object.entries(metadata).sort(([a], [b]) => {
    const aIdx = priorityFields.indexOf(a)
    const bIdx = priorityFields.indexOf(b)
    if (aIdx === -1 && bIdx === -1) return 0
    if (aIdx === -1) return 1
    if (bIdx === -1) return -1
    return aIdx - bIdx
  })

  return (
    <FieldGroup title="Metadata" defaultOpen={defaultOpen} variant="info">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {sortedEntries.map(([key, value]) => (
          <div key={key} className="bg-muted/30 p-2 rounded">
            <span className="text-xs text-muted-foreground font-medium block">
              {formatLabel(key)}
            </span>
            <span className="text-sm mt-1 block break-words">
              {formatValue(value)}
            </span>
          </div>
        ))}
      </div>
    </FieldGroup>
  )
}
