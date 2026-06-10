// Model-FREE smoke test: proves the harness plumbing end-to-end WITHOUT a vision
// LLM. It serves the child app on the web target (the same RSX as desktop/mobile),
// loads it in the bundled headless browser, waits for the wasm app to render, and
// asserts the brand wordmark + the "Begin" button via plain DOM queries.
//
// This validates everything the Midscene web tests rely on (dx serve + Puppeteer +
// wasm render) except the LLM step. Run: `npm run smoke:child:web`.
import puppeteer from "puppeteer";
import { serveDioxusWeb } from "./src/dx-server.js";

const PORT = Number(process.env.CHILD_WEB_PORT ?? 8111);

async function main(): Promise<void> {
  const server = await serveDioxusWeb({ appDir: "apps/child", port: PORT });
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 480, height: 900 });
    await page.goto(server.url, { waitUntil: "networkidle2" });

    // Wait for the Dioxus wasm app to render the brand wordmark.
    await page.waitForFunction(
      () => !!document.body && document.body.innerText.includes("PH Bulwark"),
      { timeout: 30_000 },
    );

    const hasBegin = await page.evaluate(() =>
      Array.from(document.querySelectorAll("button")).some((b) =>
        /begin/i.test(b.textContent || ""),
      ),
    );
    const text = await page.evaluate(() =>
      (document.body.innerText || "").replace(/\s+/g, " ").trim().slice(0, 160),
    );
    console.log("PAGE TEXT:", JSON.stringify(text));
    if (!hasBegin) {
      throw new Error('rendered page has no "Begin" button');
    }
    console.log(
      "SMOKE PASS — child web app served, wasm rendered the brand + 'Begin' button",
    );
  } finally {
    await browser.close().catch(() => {});
    await server.stop().catch(() => {});
  }
}

main().catch((e) => {
  console.error("SMOKE FAIL:", e);
  process.exit(1);
});
