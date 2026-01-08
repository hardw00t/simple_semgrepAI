import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { FieldGroup } from './FieldGroup'

interface CodeSectionProps {
  code: string | null
  filePath?: string
  title?: string
  defaultOpen?: boolean
}

// Detect language from file extension
function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase()
  const languageMap: Record<string, string> = {
    js: 'javascript',
    jsx: 'jsx',
    ts: 'typescript',
    tsx: 'tsx',
    py: 'python',
    java: 'java',
    go: 'go',
    rs: 'rust',
    rb: 'ruby',
    php: 'php',
    c: 'c',
    cpp: 'cpp',
    cc: 'cpp',
    h: 'c',
    hpp: 'cpp',
    cs: 'csharp',
    sh: 'bash',
    bash: 'bash',
    zsh: 'bash',
    yaml: 'yaml',
    yml: 'yaml',
    json: 'json',
    xml: 'xml',
    html: 'html',
    css: 'css',
    scss: 'scss',
    sql: 'sql',
    md: 'markdown',
    swift: 'swift',
    kt: 'kotlin',
    scala: 'scala',
  }
  return languageMap[ext || ''] || 'text'
}

export function CodeSection({
  code,
  filePath,
  title = 'Code',
  defaultOpen = true,
}: CodeSectionProps) {
  if (!code) {
    return null
  }

  const language = filePath ? detectLanguage(filePath) : 'text'

  return (
    <FieldGroup title={title} defaultOpen={defaultOpen}>
      <div className="rounded-md overflow-hidden">
        <SyntaxHighlighter
          language={language}
          style={oneDark}
          showLineNumbers
          customStyle={{
            margin: 0,
            borderRadius: '0.375rem',
            fontSize: '0.875rem',
          }}
          lineNumberStyle={{
            minWidth: '2.5em',
            paddingRight: '1em',
            color: '#636d83',
            userSelect: 'none',
          }}
        >
          {code}
        </SyntaxHighlighter>
      </div>
    </FieldGroup>
  )
}
