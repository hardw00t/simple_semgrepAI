import { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'

interface FieldGroupProps {
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
  collapsible?: boolean
  variant?: 'default' | 'danger' | 'warning' | 'success' | 'info'
}

const variantStyles = {
  default: 'bg-muted/50',
  danger: 'bg-red-500/10 text-red-600',
  warning: 'bg-yellow-500/10 text-yellow-600',
  success: 'bg-green-500/10 text-green-600',
  info: 'bg-blue-500/10 text-blue-600',
}

export function FieldGroup({
  title,
  children,
  defaultOpen = false,
  collapsible = true,
  variant = 'default',
}: FieldGroupProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  if (!collapsible) {
    return (
      <div className="border rounded-md overflow-hidden">
        <div className={`px-4 py-2 ${variantStyles[variant]}`}>
          <h4 className="text-sm font-medium">{title}</h4>
        </div>
        <div className="px-4 py-3 border-t">{children}</div>
      </div>
    )
  }

  return (
    <div className="border rounded-md overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={`flex items-center justify-between w-full px-4 py-2 text-left hover:opacity-80 transition-opacity ${variantStyles[variant]}`}
      >
        <h4 className="text-sm font-medium">{title}</h4>
        {isOpen ? (
          <ChevronUp className="h-4 w-4" />
        ) : (
          <ChevronDown className="h-4 w-4" />
        )}
      </button>
      {isOpen && <div className="px-4 py-3 border-t">{children}</div>}
    </div>
  )
}
