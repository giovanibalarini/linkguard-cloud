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

console.log(`blockGroups.check.ts: ${n} asserções OK`);
