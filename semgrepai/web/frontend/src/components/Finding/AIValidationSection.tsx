import type { FindingDetail } from '../../types'
import { CodeSection } from './CodeSection'
import { ListSection } from './ListSection'
import { ImpactGrid } from './ImpactGrid'
import { MetadataGrid } from './MetadataGrid'
import { FieldGroup } from './FieldGroup'

interface AIValidationSectionProps {
  finding: FindingDetail
}

export function AIValidationSection({ finding }: AIValidationSectionProps) {
  return (
    <div className="space-y-4">
      {/* Code Snippet */}
      <CodeSection
        code={finding.code}
        filePath={finding.path}
        title="Code Snippet"
        defaultOpen
      />

      {/* Justification */}
      {finding.justification && (
        <FieldGroup title="AI Justification" defaultOpen collapsible={false}>
          <p className="text-sm text-muted-foreground whitespace-pre-wrap">
            {finding.justification}
          </p>
        </FieldGroup>
      )}

      {/* Impact, Vulnerability, Technical Details */}
      <ImpactGrid
        impactAssessment={finding.impact_assessment}
        vulnerabilityCategory={finding.vulnerability_category}
        technicalDetails={finding.technical_details}
        defaultOpen
      />

      {/* Attack Vectors */}
      <ListSection
        title="Attack Vectors"
        items={finding.attack_vectors || []}
        variant="danger"
      />

      {/* Trigger Steps */}
      <ListSection
        title="Steps to Trigger"
        items={finding.trigger_steps || []}
        ordered
        variant="info"
      />

      {/* Proof of Concept */}
      {finding.poc && (
        <CodeSection
          code={finding.poc}
          filePath={finding.path}
          title="Proof of Concept"
          defaultOpen={false}
        />
      )}

      {/* Recommended Fixes */}
      <ListSection
        title="Recommended Fixes"
        items={finding.recommended_fixes || []}
        variant="success"
      />

      {/* Metadata (CWE, OWASP, etc) */}
      <MetadataGrid metadata={finding.metadata} />
    </div>
  )
}
