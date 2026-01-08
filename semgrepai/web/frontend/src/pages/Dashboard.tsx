import { useStats } from '../hooks/useStats'
import { useScans } from '../hooks/useScans'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Shield,
  FileWarning,
} from 'lucide-react'

function StatCard({
  title,
  value,
  icon: Icon,
  color,
}: {
  title: string
  value: string | number
  icon: React.ElementType
  color: string
}) {
  return (
    <div className="bg-card rounded-lg p-6 border">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="text-2xl font-bold mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="h-5 w-5 text-white" />
        </div>
      </div>
    </div>
  )
}

function SeverityBar({
  distribution,
}: {
  distribution: { critical: number; high: number; medium: number; low: number }
}) {
  const total = distribution.critical + distribution.high + distribution.medium + distribution.low
  if (total === 0) return <div className="text-muted-foreground text-sm">No findings</div>

  const getWidth = (count: number) => `${(count / total) * 100}%`

  return (
    <div className="space-y-2">
      <div className="flex h-4 rounded-full overflow-hidden">
        {distribution.critical > 0 && (
          <div className="bg-red-600" style={{ width: getWidth(distribution.critical) }} />
        )}
        {distribution.high > 0 && (
          <div className="bg-orange-600" style={{ width: getWidth(distribution.high) }} />
        )}
        {distribution.medium > 0 && (
          <div className="bg-yellow-600" style={{ width: getWidth(distribution.medium) }} />
        )}
        {distribution.low > 0 && (
          <div className="bg-green-600" style={{ width: getWidth(distribution.low) }} />
        )}
      </div>
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>Critical: {distribution.critical}</span>
        <span>High: {distribution.high}</span>
        <span>Medium: {distribution.medium}</span>
        <span>Low: {distribution.low}</span>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data: stats, isLoading: statsLoading } = useStats()
  const { data: recentScans, isLoading: scansLoading } = useScans(1, 5)

  if (statsLoading || scansLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground">Overview of your security scans</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={stats?.total_scans ?? 0}
          icon={Shield}
          color="bg-blue-600"
        />
        <StatCard
          title="Total Findings"
          value={stats?.total_findings ?? 0}
          icon={FileWarning}
          color="bg-orange-600"
        />
        <StatCard
          title="Critical Findings"
          value={stats?.critical_findings_count ?? 0}
          icon={AlertTriangle}
          color="bg-red-600"
        />
        <StatCard
          title="Pending Triage"
          value={stats?.findings_needing_review ?? 0}
          icon={Clock}
          color="bg-yellow-600"
        />
      </div>

      {/* Severity Distribution */}
      <div className="bg-card rounded-lg p-6 border">
        <h2 className="text-lg font-semibold mb-4">Severity Distribution</h2>
        {stats && (
          <SeverityBar
            distribution={{
              critical: stats.severity_distribution.critical,
              high: stats.severity_distribution.high,
              medium: stats.severity_distribution.medium,
              low: stats.severity_distribution.low,
            }}
          />
        )}
      </div>

      {/* AI Verdict Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center gap-2 text-red-600 mb-2">
            <XCircle className="h-5 w-5" />
            <span className="font-medium">True Positives</span>
          </div>
          <p className="text-3xl font-bold">{stats?.verdict_distribution.true_positive ?? 0}</p>
          <p className="text-sm text-muted-foreground">Confirmed vulnerabilities</p>
        </div>
        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center gap-2 text-green-600 mb-2">
            <CheckCircle className="h-5 w-5" />
            <span className="font-medium">False Positives</span>
          </div>
          <p className="text-3xl font-bold">{stats?.verdict_distribution.false_positive ?? 0}</p>
          <p className="text-sm text-muted-foreground">Safe, no action needed</p>
        </div>
        <div className="bg-card rounded-lg p-6 border">
          <div className="flex items-center gap-2 text-yellow-600 mb-2">
            <Clock className="h-5 w-5" />
            <span className="font-medium">AI: Needs Review</span>
          </div>
          <p className="text-3xl font-bold">{stats?.verdict_distribution.needs_review ?? 0}</p>
          <p className="text-sm text-muted-foreground">AI uncertain, needs human review</p>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-card rounded-lg p-6 border">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Recent Scans</h2>
          <Link to="/scans" className="text-sm text-primary hover:underline">
            View all
          </Link>
        </div>
        {recentScans?.items.length === 0 ? (
          <p className="text-muted-foreground">No scans yet. Start your first scan!</p>
        ) : (
          <div className="space-y-3">
            {recentScans?.items.map((scan) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center justify-between p-3 rounded-lg hover:bg-muted transition-colors"
              >
                <div>
                  <p className="font-medium">{scan.name || 'Unnamed Scan'}</p>
                  <p className="text-sm text-muted-foreground">{scan.target_path}</p>
                </div>
                <div className="flex items-center gap-4">
                  <span className="text-sm text-muted-foreground">
                    {scan.total_findings} findings
                  </span>
                  <span
                    className={`px-2 py-1 rounded text-xs font-medium ${
                      scan.status === 'completed'
                        ? 'bg-green-100 text-green-800'
                        : scan.status === 'running'
                        ? 'bg-blue-100 text-blue-800'
                        : scan.status === 'failed'
                        ? 'bg-red-100 text-red-800'
                        : 'bg-gray-100 text-gray-800'
                    }`}
                  >
                    {scan.status}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
