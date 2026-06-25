// Web Worker: runs the WASM inspection engine in isolation. The main thread
// terminates this worker on timeout (the browser reclaims its memory) — the
// in-browser equivalent of the per-file process isolation used by the CLI.
importScripts('wasm_exec.js');

const go = new Go();

(async () => {
  const res = await WebAssembly.instantiateStreaming(fetch('ch.wasm'), go.importObject);
  go.run(res.instance); // registers chLoadRules / chInspect on the worker global, then parks

  const [rules, given, surn, common] = await Promise.all([
    fetch('config/rules.json').then(r => r.text()),
    fetch('config/lexicons/given_names.txt').then(r => r.text()),
    fetch('config/lexicons/surnames.txt').then(r => r.text()),
    fetch('config/lexicons/common_words.txt').then(r => r.text()),
  ]);
  const info = self.chLoadRules(rules, given, surn, common);
  postMessage({ type: 'ready', info });
})().catch(err => postMessage({ type: 'ready', info: { error: String(err) } }));

onmessage = async (e) => {
  const m = e.data;
  if (m.type !== 'inspect') return;
  let verdict;
  try {
    verdict = await self.chInspect(m.name, m.bytes); // chInspect returns a Promise
  } catch (err) {
    verdict = JSON.stringify({ verdict: 'ESCALATE', error: String(err) });
  }
  postMessage({ type: 'result', id: m.id, verdict });
};
