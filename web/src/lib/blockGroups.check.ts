import assert from 'node:assert';
import { blockEnforcement } from './blockGroups.ts';

let n = 0;
const eq = (a: unknown, b: unknown, m: string) => { assert.deepStrictEqual(a, b, m); n++; };

{
  eq(blockEnforcement(null).status, 'unknown', 'sem estado do firewall dá unknown');
  eq(blockEnforcement(undefined).status, 'unknown', 'undefined dá unknown');
  eq(blockEnforcement(false).status, 'not_applied', 'bloqueios não aplicados dá not_applied');
  eq(blockEnforcement(true).status, 'ok', 'bloqueios aplicados dá ok');
}

// O motivo e o caminho para resolver são chaves de tradução, nunca frases.
{
  const desconhecido = blockEnforcement(null);
  eq(desconhecido.reasonKey, 'svc.hosts.enforcement.unknown.reason', 'unknown aponta a chave do motivo');
  eq(desconhecido.fixKey, 'svc.hosts.enforcement.unknown.fix', 'unknown aponta a chave do conserto');
  const naoAplicado = blockEnforcement(false);
  eq(naoAplicado.reasonKey, 'svc.hosts.enforcement.notApplied.reason', 'not_applied aponta a chave do motivo');
  eq(naoAplicado.fixKey, 'svc.hosts.enforcement.notApplied.fix', 'not_applied aponta a chave do conserto');
  const ok = blockEnforcement(true);
  eq([ok.reasonKey, ok.fixKey], ['', ''], 'ok não tem motivo nem conserto');
}

console.log(`blockGroups.check.ts: ${n} asserções OK`);
