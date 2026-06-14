// Headless e2e for research.predatorhunters.co.uk: confirms client-side SPA
// navigation actually re-renders (not just URL change), plus theme toggle and
// the mobile menu, and that there are NO console/page errors.
//
// This exists because a CSP that omitted 'unsafe-eval' silently broke
// Dioxus-web's renderer (new Function) after SSG hydration — links changed the
// URL but the page never updated. Static header/route checks did not catch it;
// only a real browser clicking real links does. Run after any CSP/deploy change.
//
//   cd tools/ui-tests && npm i && node research-nav.e2e.mjs
//   (override target with BASE=https://staging... node research-nav.e2e.mjs)
//
// Exit 0 = all green; exit 1 = a regression (details printed as JSON).
import puppeteer from "puppeteer";

const BASE = process.env.BASE || "https://research.predatorhunters.co.uk";
const browser = await puppeteer.launch({ headless: "new", args: ["--no-sandbox"] });
const page = await browser.newPage();
const errors = [];
page.on("console", (m) => { if (m.type() === "error") errors.push(`[console] ${m.text().slice(0, 200)}`); });
page.on("pageerror", (e) => errors.push(`[pageerror] ${e.message.slice(0, 200)}`));
page.on("requestfailed", (r) => errors.push(`[reqfailed] ${r.url()} ${r.failure()?.errorText}`));

const h1 = () => page.evaluate(() => document.querySelector("h1")?.innerText?.replace(/\s+/g, " ").slice(0, 48) || "");
const goto = (p) => page.goto(`${BASE}${p}`, { waitUntil: "networkidle2", timeout: 45000 });
const hydrate = () => new Promise((r) => setTimeout(r, 4000));
const settle = () => new Promise((r) => setTimeout(r, 1200));
const clickHref = (href) => page.evaluate((h) => {
  const a = [...document.querySelectorAll("a")].find((x) => (x.getAttribute("href") || "") === h);
  if (!a) return false; a.click(); return true;
}, href);

// Each pair: navigate to `from`, click the link to `to`, assert URL + H1 change w/o reload.
const hops = [
  ["/", "/research"], ["/research", "/coverage"], ["/coverage", "/systems"],
  ["/systems", "/systems/ph-camera"], ["/systems", "/systems/ph-bulwark"],
  ["/systems", "/waitlist"], ["/", "/approach"], ["/", "/about"],
  ["/", "/contact"], ["/", "/download"], ["/download", "/security"], ["/", "/privacy"],
];
const results = [];
for (const [from, to] of hops) {
  await goto(from); await hydrate();
  const before = await h1();
  const clicked = await clickHref(to);
  await settle();
  const url = await page.evaluate(() => location.pathname);
  const after = await h1();
  results.push({ from, to, ok: clicked && url === to && after.length > 0 && after !== before });
}

// theme toggle flips <html data-theme>
await goto("/"); await hydrate();
const t0 = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
await page.evaluate(() => document.querySelector(".theme-toggle")?.click());
await new Promise((r) => setTimeout(r, 500));
const t1 = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
const themeOk = !!t0 && !!t1 && t0 !== t1;

// mobile burger opens the menu
await page.setViewport({ width: 390, height: 844 });
await new Promise((r) => setTimeout(r, 600));
await page.evaluate(() => document.querySelector(".nav-burger")?.click());
await new Promise((r) => setTimeout(r, 500));
const menuOk = await page.evaluate(() => !!document.querySelector("#nav-menu"));

const navOk = results.every((r) => r.ok);
const pass = navOk && themeOk && menuOk && errors.length === 0;
console.log(JSON.stringify({
  pass, navOk, themeOk, menuOk,
  failed: results.filter((r) => !r.ok),
  errors: errors.length ? errors : "none",
}, null, 2));
await browser.close();
process.exit(pass ? 0 : 1);
