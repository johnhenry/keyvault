// Runs the runtime-neutral cases under node:test (and under `deno test`, which understands the same imports).
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { makeCases } from '../cases.mjs';

const dir = new URL('../fixtures/', import.meta.url);
const env = { fixture: (name) => readFile(new URL(name, dir), 'utf8') };
for (const c of makeCases(env)) test(c.name, c.run);
