/**
 * Busca, uma vez, o que o LinkGuard já sabe da rede e devolve pronto para o
 * seletor de alvos.
 *
 * Fica separado do componente porque a tradução (quem é host, o que agrupar)
 * mora em lib/netTargets, que é código puro e coberto por asserção. Aqui só
 * entra o I/O.
 *
 * As chamadas são toleradas individualmente: falhar uma não pode deixar a
 * lista de APARELHOS sem aparecer. Falhar tudo junto degrada o seletor para
 * "digite o endereço", que é o comportamento de antes — nunca uma tela
 * quebrada.
 */

import { useEffect, useState } from 'react';
import client from '../api/client';
import { buildTargets, type Target, type HostLike } from './netTargets';

export function useNetTargets(): { targets: Target[]; carregando: boolean } {
  const [targets, setTargets] = useState<Target[]>([]);
  const [carregando, setCarregando] = useState(true);

  useEffect(() => {
    let vivo = true;
    (async () => {
      const pega = async <T,>(url: string, extrai: (d: unknown) => T[]): Promise<T[]> => {
        try {
          const r = await client.get(url);
          return extrai(r.data) || [];
        } catch {
          return [];
        }
      };

      const hosts = await pega<HostLike>('/api/hosts', (d) => (Array.isArray(d) ? d : (d as { hosts?: HostLike[] })?.hosts ?? []));

      if (!vivo) return;
      // A rede local vinha do CIDR do DHCP, que a versão cloud não tem. Volta
      // como alias de rede no redesenho do firewall.
      setTargets(buildTargets(hosts, '', Date.now()));
      setCarregando(false);
    })();
    return () => { vivo = false; };
  }, []);

  return { targets, carregando };
}
