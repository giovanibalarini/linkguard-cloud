// Tipos e utilitários da tela de VPN. Os componentes de web/src/components/vpn
// e a página web/src/pages/Vpn.tsx compartilham este arquivo.

export type T = (key: string, vars?: Record<string, string | number>) => string;

export type AccessMode = 'full' | 'restricted';
export type TunnelMode = 'full' | 'split';

export interface VPNConfig {
  enabled: boolean;
  listen_port: number;
  address: string;
  endpoint_host: string;
}

export interface VPNPeer {
  user_id: string;
  username: string;
  public_key: string;
  address: string;
  firewall_group_id: string;
  access_mode?: AccessMode;
  allowed_host_groups?: string[];
  allowed_ports?: string;
  tunnel_mode?: TunnelMode;
  extra_routes?: string[];
  mtu?: number;
  // O perfil mudou depois que a pessoa baixou o arquivo. O WireGuard não empurra
  // rota para um cliente já configurado: ela precisa baixar de novo.
  config_stale?: boolean;
  created_at?: number;
  rotated_at?: number;
  online?: boolean;
  endpoint?: string;
  latest_handshake?: number;
  transfer_rx?: number;
  transfer_tx?: number;
  latency_ms?: number;
}

export interface VPNOverview {
  config: VPNConfig;
  public_key?: string;
  peers: VPNPeer[];
  running: boolean;
  last_apply_ok: boolean;
  last_apply_error?: string;
  last_applied_at?: number;
}

export interface VPNEnrollment {
  peer: VPNPeer;
  client_config: string;
  qr_data_url?: string;
  apply_error?: string;
  warning?: string;
}

export interface Reach {
  name: string;
  hosts: string[];
  ports?: string;
}

// GET /api/vpn/me: só a VPN de quem pergunta.
export interface MyVPN {
  enabled: boolean;
  running: boolean;
  endpoint?: string;
  peer?: VPNPeer;
  reach: Reach[];
}

export interface Candidate {
  id: string;
  username: string;
}

export interface AccessProfile {
  access_mode: AccessMode;
  allowed_host_groups: string[];
  allowed_ports: string;
  tunnel_mode: TunnelMode;
  extra_routes: string[];
  mtu: number;
}

// Para dar acesso a outra pessoa, o ponto de partida é o mínimo: só os destinos
// escolhidos, com o resto da internet dela fora do túnel.
export const restrictedProfile: AccessProfile = {
  access_mode: 'restricted',
  allowed_host_groups: [],
  allowed_ports: '',
  tunnel_mode: 'split',
  extra_routes: [],
  mtu: 0,
};

export function profileOf(peer: VPNPeer): AccessProfile {
  return {
    access_mode: peer.access_mode === 'restricted' ? 'restricted' : 'full',
    allowed_host_groups: peer.allowed_host_groups || [],
    allowed_ports: peer.allowed_ports || '',
    tunnel_mode: peer.tunnel_mode === 'split' ? 'split' : 'full',
    extra_routes: peer.extra_routes || [],
    mtu: peer.mtu || 0,
  };
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function ago(epoch: number): string {
  const diff = Math.max(0, Math.floor(Date.now() / 1000) - epoch);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)} min`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ${Math.floor((diff % 3600) / 60)} min`;
  return `${Math.floor(diff / 86400)} d`;
}

// A situação do peer em uma frase: é o que o admin quer saber primeiro.
export function lastSeen(peer: VPNPeer, t: T): string {
  if (peer.online) return t('vpn.seen.now');
  if (peer.latest_handshake && peer.latest_handshake > 0) return t('vpn.seen.ago', { time: ago(peer.latest_handshake) });
  return t('vpn.seen.never');
}

export function apiError(error: unknown, fallback: string): string {
  const value = error as { response?: { data?: { error?: string } } };
  return value.response?.data?.error || fallback;
}

export function safeName(value: string): string {
  return value.normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'client';
}

// "porta 6443" ou "portas 5432, 6432": o texto de portas liberadas, no plural
// certo. `base` é o prefixo da chave (vpn.list ou vpn.me).
export function portsText(ports: string, base: 'vpn.list' | 'vpn.me', t: T): string {
  const list = ports.split(',').map((p) => p.trim()).filter(Boolean);
  const many = list.length > 1 || list.some((p) => p.includes('-'));
  return t(many ? `${base}.ports` : `${base}.port`, { ports: list.join(', ') });
}
