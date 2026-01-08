import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsApi, FindingsParams } from '../api/client'
import type { FindingUpdate } from '../types'

export function useFindings(scanId: string, params: FindingsParams = {}) {
  return useQuery({
    queryKey: ['findings', scanId, params],
    queryFn: () => findingsApi.list(scanId, params),
    enabled: !!scanId,
  })
}

export function useFinding(scanId: string, findingId: string) {
  return useQuery({
    queryKey: ['finding', scanId, findingId],
    queryFn: () => findingsApi.get(scanId, findingId),
    enabled: !!scanId && !!findingId,
  })
}

export function useUpdateFinding(scanId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ findingId, update }: { findingId: string; update: FindingUpdate }) =>
      findingsApi.update(scanId, findingId, update),
    onSuccess: (_, { findingId }) => {
      queryClient.invalidateQueries({ queryKey: ['finding', scanId, findingId] })
      queryClient.invalidateQueries({ queryKey: ['findings', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}

export function useBulkTriage(scanId: string) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ findingIds, triageStatus, triageNote }: { findingIds: string[]; triageStatus: string; triageNote?: string }) =>
      findingsApi.bulkTriage(scanId, findingIds, triageStatus, triageNote),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}
