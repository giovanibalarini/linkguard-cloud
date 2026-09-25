import { useCallback, useEffect, useRef, useState } from 'react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { EstadoFW } from '../types/firewall';

export function useFirewallEstado() {
  const { can } = useAuth();
  const canRead = can('firewall.read');
  const [estado, setEstado] = useState<EstadoFW | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const canReadRef = useRef(canRead);
  canReadRef.current = canRead;

  const refresh = useCallback(async () => {
    if (!canReadRef.current) {
      setLoading(false);
      return;
    }
    try {
      const { data } = await client.get<EstadoFW>('/api/firewall/estado');
      setEstado(data);
      setError(null);
    } catch (e: any) {
      setError(e.response?.data?.error || e.message || 'Erro ao carregar estado do firewall');
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!canRead) return;

    const interval = setInterval(() => {
      if (document.visibilityState !== 'hidden') {
        refreshRef.current();
      }
    }, 5000);

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') {
        refreshRef.current();
      }
    };

    document.addEventListener('visibilitychange', onVisibilityChange);

    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, [canRead]);

  return { estado, loading, error, refresh };
}
