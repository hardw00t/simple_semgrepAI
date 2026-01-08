import { FieldGroup } from './FieldGroup'

interface ListSectionProps {
  title: string
  items: string[]
  ordered?: boolean
  defaultOpen?: boolean
  variant?: 'default' | 'danger' | 'warning' | 'success' | 'info'
}

export function ListSection({
  title,
  items,
  ordered = false,
  defaultOpen = false,
  variant = 'default',
}: ListSectionProps) {
  if (!items || items.length === 0) {
    return null
  }

  const ListTag = ordered ? 'ol' : 'ul'
  const listStyle = ordered ? 'list-decimal' : 'list-disc'

  return (
    <FieldGroup title={title} defaultOpen={defaultOpen} variant={variant}>
      <ListTag className={`${listStyle} list-inside space-y-2`}>
        {items.map((item, idx) => (
          <li key={idx} className="text-sm text-muted-foreground">
            {item}
          </li>
        ))}
      </ListTag>
    </FieldGroup>
  )
}
