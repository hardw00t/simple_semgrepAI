import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansApi } from '../api/client'
import type { ScanCreate } from '../types'

export function useScans(page = 1, pageSize = 20, status?: string) {
  return useQuery({
    queryKey: ['scans', page, pageSize, status],
    queryFn: () => scansApi.list(page, pageSize, status),
  })
}

export function useScan(scanId: string) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => {
      // Refetch every 2 seconds if scan is running
      const scan = query.state.data
      if (scan?.status === 'running' || scan?.status === 'pending') {
        return 2000
      }
      return false
    },
  })
}

export function useCreateScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (scan: ScanCreate) => scansApi.create(scan),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['scans'],
        refetchType: 'all'
      })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}

export function useDeleteScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (scanId: string) => scansApi.delete(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}

export function useCancelScan() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (scanId: string) => scansApi.cancel(scanId),
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}
