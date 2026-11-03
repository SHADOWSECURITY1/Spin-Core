// Consumers load @spin/core with require() as well as import: React Native
// code compiled to CommonJS, Jest, tsx on a non-"type: module" package. Every
// export must resolve both ways (Node 20.19+/22 can require() ESM).
const assert = require('node:assert/strict');
// Resolved through the package's own name (Node self-reference), so this
// exercises the real "exports" map exactly as a consumer would.
const req = (sub) => require(`@spin/core${sub}`);

(async () => {
  for (const [sub, fn] of [['', 'PayEnvelopeService'], ['/vault', 'encryptMessage'], ['/testing', 'payEnvelopeStoreConformance'], ['/approval', 'approveIntent'], ['/agent', 'SpinAgent']]) {
    assert.equal(typeof req(sub)[fn], 'function', `require('@spin/core${sub}')`);
    assert.equal(typeof (await import(`@spin/core${sub}`))[fn], 'function', `import('@spin/core${sub}')`);
  }
  console.log('packaging: require() and import() resolve every export');
})().catch((e) => { console.error(e); process.exit(1); });
