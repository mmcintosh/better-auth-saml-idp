/** `s` without trailing slashes (a loop: `/\/+$/` is quadratic on many slashes, D-037). */
export function trimSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s[end - 1] === "/") end--;
  return s.slice(0, end);
}
