import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useScans, useCreateScan, useDeleteScan } from '../hooks/useScans'
import { Plus, Trash2, FolderOpen, Clock, CheckCircle, XCircle, Loader } from 'lucide-react'
import type { ScanStatus } from '../types'

function StatusBadge({ status }: { status: ScanStatus }) {
  const config = {
    pending: { color: 'bg-gray-100 text-gray-800', icon: Clock },
    running: { color: 'bg-blue-100 text-blue-800', icon: Loader },
    completed: { color: 'bg-green-100 text-green-800', icon: CheckCircle },
    failed: { color: 'bg-red-100 text-red-800', icon: XCircle },
    cancelled: { color: 'bg-yellow-100 text-yellow-800', icon: XCircle },
  }

  const { color, icon: Icon } = config[status]

  return (
    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${color}`}>
      <Icon className={`h-3 w-3 ${status === 'running' ? 'animate-spin' : ''}`} />
      {status}
    </span>
  )
}

function NewScanDialog({
  isOpen,
  onClose,
  onSubmit,
  isLoading,
}: {
  isOpen: boolean
  onClose: () => void
  onSubmit: (data: { target_path: string; name?: string; rules_path?: string }) => void
  isLoading: boolean
}) {
  const [targetPath, setTargetPath] = useState('')
  const [name, setName] = useState('')
  const [rulesPath, setRulesPath] = useState('')

  if (!isOpen) return null

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSubmit({
      target_path: targetPath,
      name: name || undefined,
      rules_path: rulesPath || undefined,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-card rounded-lg p-6 w-full max-w-md border">
        <h2 className="text-lg font-semibold mb-4">New Scan</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Target Path *</label>
            <input
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/code"
              className="w-full px-3 py-2 border rounded-md bg-background"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Scan Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Optional scan name"
              className="w-full px-3 py-2 border rounded-md bg-background"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Custom Rules Path</label>
            <input
              type="text"
              value={rulesPath}
              onChange={(e) => setRulesPath(e.target.value)}
              placeholder="/path/to/rules.yml (optional)"
              className="w-full px-3 py-2 border rounded-md bg-background"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm border rounded-md hover:bg-muted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || !targetPath}
              className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded-md hover:opacity-90 disabled:opacity-50"
            >
              {isLoading ? 'Starting...' : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Scans() {
  const [page, setPage] = useState(1)
  const [isNewScanOpen, setIsNewScanOpen] = useState(false)
  const navigate = useNavigate()
  const { data: scans, isLoading } = useScans(page, 20)
  const createScan = useCreateScan()
  const deleteScan = useDeleteScan()

  const handleCreateScan = (data: { target_path: string; name?: string; rules_path?: string }) => {
    createScan.mutate(data, {
      onSuccess: (newScan) => {
        setIsNewScanOpen(false)
        navigate(`/scans/${newScan.id}`)
      },
    })
  }

  const handleDeleteScan = (scanId: string) => {
    if (confirm('Are you sure you want to delete this scan?')) {
      deleteScan.mutate(scanId)
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scans</h1>
          <p className="text-muted-foreground">Manage your security scans</p>
        </div>
        <button
          onClick={() => setIsNewScanOpen(true)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:opacity-90"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </div>

      {scans?.items.length === 0 ? (
        <div className="bg-card rounded-lg p-12 border text-center">
          <FolderOpen className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
          <h3 className="text-lg font-medium mb-2">No scans yet</h3>
          <p className="text-muted-foreground mb-4">Start your first security scan to find vulnerabilities.</p>
          <button
            onClick={() => setIsNewScanOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:opacity-90"
          >
            <Plus className="h-4 w-4" />
            New Scan
          </button>
        </div>
      ) : (
        <div className="bg-card rounded-lg border">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b">
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Name</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground hidden sm:table-cell">Target</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground">Findings</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground hidden md:table-cell">Progress</th>
                  <th className="px-4 py-3 text-left text-sm font-medium text-muted-foreground hidden lg:table-cell">Created</th>
                  <th className="px-4 py-3 text-right text-sm font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans?.items.map((scan) => (
                  <tr key={scan.id} className="border-b last:border-b-0 hover:bg-muted/50">
                    <td className="px-4 py-3">
                      <Link
                        to={`/scans/${scan.id}`}
                        className="font-medium hover:text-primary"
                      >
                        {scan.name || 'Unnamed Scan'}
                      </Link>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground hidden sm:table-cell">
                      <span
                        className="block max-w-[200px] lg:max-w-xs truncate"
                        title={scan.target_path}
                      >
                        {scan.target_path}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-4 py-3 text-sm">{scan.total_findings}</td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      <div className="w-24">
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary transition-all"
                            style={{ width: `${scan.progress_percentage}%` }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {scan.progress_percentage.toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground hidden lg:table-cell">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleDeleteScan(scan.id)}
                        disabled={scan.status === 'running'}
                        className="p-2 text-muted-foreground hover:text-destructive disabled:opacity-50"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {scans && scans.total_pages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t">
              <span className="text-sm text-muted-foreground">
                Page {scans.page} of {scans.total_pages}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-3 py-1 text-sm border rounded-md disabled:opacity-50"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(scans.total_pages, p + 1))}
                  disabled={page === scans.total_pages}
                  className="px-3 py-1 text-sm border rounded-md disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      <NewScanDialog
        isOpen={isNewScanOpen}
        onClose={() => setIsNewScanOpen(false)}
        onSubmit={handleCreateScan}
        isLoading={createScan.isPending}
      />
    </div>
  )
}
