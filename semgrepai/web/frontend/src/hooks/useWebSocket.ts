import { useEffect, useRef, useCallback, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { WebSocketMessage } from '../types'

interface UseWebSocketOptions {
  scanId: string
  onProgress?: (validated: number, total: number) => void
  onFindingValidated?: (findingId: string) => void
  onComplete?: () => void
  onError?: (error: string) => void
}

export function useWebSocket({
  scanId,
  onProgress,
  onFindingValidated,
  onComplete,
  onError,
}: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null)
  const queryClient = useQueryClient()
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const reconnectAttempts = useRef(0)
  const maxReconnectAttempts = 5

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/ws/scans/${scanId}`

    const ws = new WebSocket(wsUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setIsConnected(true)
      reconnectAttempts.current = 0
    }

    ws.onmessage = (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data)
        setLastMessage(message)

        switch (message.type) {
          case 'progress':
            if (message.data && onProgress) {
              onProgress(
                message.data.validated_findings ?? 0,
                message.data.total_findings ?? 0
              )
            }
            // Invalidate scan query to get fresh data
            queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
            break

          case 'finding_validated':
            if (message.data?.finding_id && onFindingValidated) {
              onFindingValidated(String(message.data.finding_id))
            }
            // Invalidate findings query to get fresh data
            queryClient.invalidateQueries({ queryKey: ['findings', scanId] })
            break

          case 'complete':
            if (onComplete) {
              onComplete()
            }
            // Invalidate all related queries
            queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
            queryClient.invalidateQueries({ queryKey: ['findings', scanId] })
            queryClient.invalidateQueries({ queryKey: ['stats'] })
            break

          case 'error':
            if (message.message && onError) {
              onError(message.message)
            }
            break
        }
      } catch (e) {
        console.error('Failed to parse WebSocket message:', e)
      }
    }

    ws.onerror = (error) => {
      console.error('WebSocket error:', error)
      setIsConnected(false)
    }

    ws.onclose = () => {
      setIsConnected(false)
      wsRef.current = null

      // Attempt to reconnect if not at max attempts
      if (reconnectAttempts.current < maxReconnectAttempts) {
        reconnectAttempts.current += 1
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000)
        setTimeout(connect, delay)
      }
    }
  }, [scanId, onProgress, onFindingValidated, onComplete, onError, queryClient])

  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
    setIsConnected(false)
  }, [])

  useEffect(() => {
    connect()
    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  return {
    isConnected,
    lastMessage,
    connect,
    disconnect,
  }
}

export function useScanProgress(scanId: string) {
  const [progress, setProgress] = useState({
    validated: 0,
    total: 0,
    percentage: 0,
  })
  const [status, setStatus] = useState<'connecting' | 'running' | 'complete' | 'error'>('connecting')
  const [error, setError] = useState<string | null>(null)

  const { isConnected } = useWebSocket({
    scanId,
    onProgress: (validated, total) => {
      setProgress({
        validated,
        total,
        percentage: total > 0 ? (validated / total) * 100 : 0,
      })
      setStatus('running')
    },
    onComplete: () => {
      setStatus('complete')
    },
    onError: (err) => {
      setError(err)
      setStatus('error')
    },
  })

  useEffect(() => {
    if (isConnected && status === 'connecting') {
      setStatus('running')
    }
  }, [isConnected, status])

  return {
    progress,
    status,
    error,
    isConnected,
  }
}
