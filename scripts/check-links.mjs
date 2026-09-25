// Checks every relative link and #anchor in the README and docs/ (GitHub heading slugs).
//   node scripts/check-links.mjs
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize } from "node:path";

const strip = (s) => s.replace(/```[\s\S]*?```/g, "");
const slug = (h) => h.trim().toLowerCase().replace(/<[^>]+>/g, "").replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/ /g, "-");
const headings = (f) => [...strip(readFileSync(f, "utf8")).matchAll(/^#{1,6} (.+)$/gm)].map((m) => slug(m[1]));
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));

const files = ["README.md", "CHANGELOG.md", ...walk("docs").filter((f) => f.endsWith(".md"))];
const bad = [];
let count = 0;
for (const f of files) {
  for (const m of strip(readFileSync(f, "utf8")).matchAll(/\]\(([^)\s]+)\)/g)) {
    const link = m[1];
    if (/^(https?:|mailto:)/.test(link)) continue;
    count++;
    const [p, anchor] = link.split("#");
    const target = p ? normalize(join(dirname(f), p)) : f;
    if (!existsSync(target)) bad.push(`${f} -> ${link} (no such file)`);
    else if (anchor && target.endsWith(".md") && !headings(target).includes(decodeURIComponent(anchor))) bad.push(`${f} -> ${link} (no such heading)`);
  }
}
console.log(`${count} links checked`);
for (const b of bad) console.log(`  ${b}`);
process.exit(bad.length ? 1 : 0);
