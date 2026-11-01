/**
 * Luhn arithmetic for the synthetic presentation PANs a Pay Envelope hands
 * out. These are never real card numbers: they only need to pass the format
 * checks a card form or gateway applies.
 */

/** Luhn check digit for a 15-digit seed. */
export function luhnCheckDigit(digits15: string): string {
  if (!/^\d+$/.test(digits15)) throw new Error("Luhn seed must be numeric");
  let sum = 0;
  for (let i = 0; i < digits15.length; i++) {
    let d = Number(digits15[digits15.length - 1 - i]);
    if (i % 2 === 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return String((10 - (sum % 10)) % 10);
}

/** True for a 16-digit string whose last digit is its Luhn check digit. */
export function isValidLuhn(pan: string): boolean {
  if (!/^\d{16}$/.test(pan)) return false;
  return luhnCheckDigit(pan.slice(0, 15)) === pan[15];
}

/** BIN (6 digits) + body (9 digits) + Luhn check digit = 16-digit PAN. */
export function projectPan(bin6: string, body9: string): string {
  if (!/^\d{6}$/.test(bin6)) throw new Error("BIN must be 6 digits");
  if (!/^\d{9}$/.test(body9)) throw new Error("PAN body must be 9 digits");
  const seed = `${bin6}${body9}`;
  return `${seed}${luhnCheckDigit(seed)}`;
}
