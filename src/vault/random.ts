import { randomBytes } from '@noble/hashes/utils.js';

/**
 * Cryptographically secure random bytes from crypto.getRandomValues.
 *
 * React Native's Hermes engine doesn't provide it: the app must load a
 * polyfill (e.g. `import 'react-native-get-random-values'` first thing in
 * index.js). Without one this throws instead of ever falling back to a
 * weaker source.
 */
export function secureRandom(length: number): Uint8Array {
  const c = (globalThis as { crypto?: { getRandomValues?: unknown } }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error(
      'No secure random source: crypto.getRandomValues is unavailable. ' +
        "In React Native, import 'react-native-get-random-values' before any SPIN crypto.",
    );
  }
  return randomBytes(length);
}
