import { afterAll, beforeAll, describe, it } from "vitest";
import { PuppeteerAgent } from "@midscene/web/puppeteer";
import puppeteer, { type Browser, type Page } from "puppeteer";
import { serveDioxusWeb, type DxServer } from "../src/dx-server.js";

/**
 * Child onboarding "setup journey" — the PRIMARY, always-runnable cross-platform
 * check. It serves apps/child on the web target (the same RSX that drives
 * desktop/mobile) and drives it with Midscene's vision agent in natural language:
 *
 *   Welcome -> How it works -> Permissions (x3 grant) -> Pair (6-char code) -> Done
 *
 * Asserts the "PH Bulwark Shield" brand and the final "Protection is active" state.
 */
const PORT = Number(process.env.CHILD_WEB_PORT ?? 8111);
const HEADLESS = process.env.MIDSCENE_HEADED ? false : true;

describe("child onboarding (web)", () => {
  let server: DxServer;
  let browser: Browser;
  let page: Page;
  let agent: PuppeteerAgent;

  beforeAll(async () => {
    server = await serveDioxusWeb({ appDir: "apps/child", port: PORT });

    browser = await puppeteer.launch({
      headless: HEADLESS,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    page = await browser.newPage();
    await page.setViewport({ width: 480, height: 900, deviceScaleFactor: 1 });
    await page.goto(server.url, { waitUntil: "networkidle2" });

    agent = new PuppeteerAgent(page);
  });

  afterAll(async () => {
    await agent?.destroy?.().catch(() => {});
    await browser?.close().catch(() => {});
    await server?.stop().catch(() => {});
  });

  it("walks the full setup journey to 'Protection is active'", async () => {
    // Step 1 — Welcome
    await agent.aiAssert(
      'The "PH Bulwark Shield" brand wordmark is visible at the top of the page',
    );
    await agent.aiAssert('A primary "Begin" button is visible');
    await agent.aiTap('the "Begin" button');

    // Step 2 — How it works
    await agent.aiAssert(
      'The screen explains what PH Bulwark does, with a heading like "What PH Bulwark does"',
    );
    await agent.aiTap('the "I understand" button');

    // Step 3 — Permissions: grant all three
    await agent.aiAssert(
      "The screen shows three permissions to grant (Accessibility, Safe browsing / VPN, Stay-on protection)",
    );
    // Tap each "Grant" button in turn. After each grant the row flips to a check,
    // so the next "Grant" is the topmost remaining one.
    await agent.aiTap('the first "Grant" button (for the Accessibility permission)');
    await agent.aiTap('the next remaining "Grant" button (Safe browsing / VPN permission)');
    await agent.aiTap('the last remaining "Grant" button (Stay-on protection permission)');

    await agent.aiAssert("All three permissions now show as granted (a check mark, not a Grant button)");
    await agent.aiTap('the enabled "Continue" button');

    // Step 4 — Pair: enter a 6-character code
    await agent.aiAssert('The screen asks to connect to the console and shows a pairing-code input');
    await agent.aiInput("ABC123", "the pairing-code text input field");
    await agent.aiTap('the "Connect" button');

    // Step 5 — Done
    await agent.aiAssert('The page shows the heading "Protection is active."');
  });
});
