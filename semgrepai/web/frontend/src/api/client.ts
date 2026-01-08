import axios from 'axios'
import type { Scan, ScanCreate, ScanDetail, Finding, FindingDetail, FindingUpdate, Stats, PaginatedResponse } from '../types'

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Scans API
export const scansApi = {
  list: async (page = 1, pageSize = 20, status?: string): Promise<PaginatedResponse<Scan>> => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (status) params.append('status', status)
    const { data } = await api.get(`/scans?${params}`)
    return data
  },

  get: async (scanId: string): Promise<ScanDetail> => {
    const { data } = await api.get(`/scans/${scanId}`)
    return data
  },

  create: async (scan: ScanCreate): Promise<Scan> => {
    const { data } = await api.post('/scans', scan)
    return data
  },

  delete: async (scanId: string): Promise<void> => {
    await api.delete(`/scans/${scanId}`)
  },

  cancel: async (scanId: string): Promise<Scan> => {
    const { data } = await api.post(`/scans/${scanId}/cancel`)
    return data
  },
}

// Findings API
export interface FindingsParams {
  page?: number
  pageSize?: number
  severity?: string
  triageStatus?: string
  verdict?: string
  ruleId?: string
  pathContains?: string
  minRiskScore?: number
  maxRiskScore?: number
  assignee?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

export const findingsApi = {
  list: async (scanId: string, params: FindingsParams = {}): Promise<PaginatedResponse<Finding>> => {
    const searchParams = new URLSearchParams()
    if (params.page) searchParams.append('page', String(params.page))
    if (params.pageSize) searchParams.append('page_size', String(params.pageSize))
    if (params.severity) searchParams.append('severity', params.severity)
    if (params.triageStatus) searchParams.append('triage_status', params.triageStatus)
    if (params.verdict) searchParams.append('verdict', params.verdict)
    if (params.ruleId) searchParams.append('rule_id', params.ruleId)
    if (params.pathContains) searchParams.append('path_contains', params.pathContains)
    if (params.minRiskScore !== undefined) searchParams.append('min_risk_score', String(params.minRiskScore))
    if (params.maxRiskScore !== undefined) searchParams.append('max_risk_score', String(params.maxRiskScore))
    if (params.assignee) searchParams.append('assignee', params.assignee)
    if (params.sortBy) searchParams.append('sort_by', params.sortBy)
    if (params.sortOrder) searchParams.append('sort_order', params.sortOrder)

    const { data } = await api.get(`/scans/${scanId}/findings?${searchParams}`)
    return data
  },

  get: async (scanId: string, findingId: string): Promise<FindingDetail> => {
    const { data } = await api.get(`/scans/${scanId}/findings/${findingId}`)
    return data
  },

  update: async (scanId: string, findingId: string, update: FindingUpdate): Promise<FindingDetail> => {
    const { data } = await api.patch(`/scans/${scanId}/findings/${findingId}`, update)
    return data
  },

  bulkTriage: async (scanId: string, findingIds: string[], triageStatus: string, triageNote?: string): Promise<{ updated_count: number }> => {
    const { data } = await api.post(`/scans/${scanId}/findings/bulk-triage`, {
      finding_ids: findingIds,
      triage_status: triageStatus,
      triage_note: triageNote,
    })
    return data
  },
}

// Stats API
export const statsApi = {
  get: async (): Promise<Stats> => {
    const { data } = await api.get('/stats')
    return data
  },
}

export default api
