import { tStatic } from '../i18n';
import type { ProblemaFW } from '../types/firewall';

/**
 * errMsg tira do erro do axios a mensagem que o BACKEND escreveu, e só cai no
 * genérico quando não há nenhuma.
 *
 * Isso importa mais aqui do que parece: é o backend que sabe dizer "não foi
 * possível concluir a reversão; o LinkGuard vai tentar de novo sozinho" ou por
 * que o `nft -c` recusou a regra. Trocar essa frase por "erro interno do
 * servidor" tira do operador justamente o que ele precisa para agir.
 *
 * O corpo de erro do backend é sempre {"error": "..."}; a validação do firewall
 * por zonas acrescenta "problemas": [{...}], onde cada problema é uma chave do
 * dicionário (+ vars), não texto.
 * Os problemas são traduzidos aqui, com o mesmo `t(p.chave, p.vars)` que a
 * barra de pendências e o preview do editor usam, e vão depois da frase.
 *
 * `t` vem por parâmetro para o idioma seguir a troca em tempo real; sem ele,
 * cai no tStatic (idioma guardado), que serve a quem está fora da árvore React.
 */
type Traduz = (key: string, vars?: Record<string, string | number>) => string;

interface CorpoErro {
  error?: string;
  problemas?: ProblemaFW[];
}

export function errMsg(e: unknown, t: Traduz = tStatic): string {
  const ax = e as { response?: { data?: CorpoErro }; message?: string };
  const corpo = ax?.response?.data;
  const frase = corpo?.error || ax?.message || t('common.error');
  const problemas = Array.isArray(corpo?.problemas) ? corpo.problemas : [];
  if (problemas.length === 0) return frase;
  return `${frase}: ${problemas.map((p) => t(p.chave, p.vars)).join('; ')}`;
}
