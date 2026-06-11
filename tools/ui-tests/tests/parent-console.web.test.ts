import { afterAll, beforeAll, describe, it } from "vitest";
import { PuppeteerAgent } from "@midscene/web/puppeteer";
import puppeteer, { type Browser, type Page } from "puppeteer";
import { serveDioxusWeb, type DxServer } from "../src/dx-server.js";

/**
 * Parent console (PH Bulwark Manager) — a lighter smoke test: the dark-theme
 * console loads, the brand is visible, and the six nav tabs are reachable.
 *
 * IMPORTANT: apps/parent currently pins `dioxus = { features = ["desktop"] }`
 * and pulls native deps (tonic / winreg / windows), so it does NOT build for the
 * web target out of the box. The README documents the one-time Cargo.toml edit
 * required to serve it on web. Until that edit is applied, `dx serve` will fail
 * and this test errors out in beforeAll with a clear message (it does not silently
 * pass). The child web test is the primary always-runnable path.
 */
const PORT = Number(process.env.PARENT_WEB_PORT ?? 8112);
const HEADLESS = process.env.MIDSCENE_HEADED ? false : true;

const TABS = ["Setup", "Alerts", "Children", "Protection", "Server", "Coverage"] as const;

describe("parent console (web)", () => {
  let server: DxServer;
  let browser: Browser;
  let page: Page;
  let agent: PuppeteerAgent;

  beforeAll(async () => {
    server = await serveDioxusWeb({ appDir: "apps/parent", port: PORT });

    browser = await puppeteer.launch({
      headless: HEADLESS,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    page = await browser.newPage();
    await page.setViewport({ width: 1200, height: 900, deviceScaleFactor: 1 });
    await page.goto(server.url, { waitUntil: "networkidle2" });

    agent = new PuppeteerAgent(page);
  });

  afterAll(async () => {
    await agent?.destroy?.().catch(() => {});
    await browser?.close().catch(() => {});
    await server?.stop().catch(() => {});
  });

  it("shows the brand and the six nav tabs", async () => {
    await agent.aiAssert('The "PH Bulwark Manager" title is visible at the top of the console');
    await agent.aiAssert(
      "A horizontal tab bar is visible with tabs: Setup, Alerts, Children, Protection, Server, and Coverage",
    );
  });

  it("can reach each of the six nav tabs", async () => {
    for (const tab of TABS) {
      await agent.aiTap(`the "${tab}" navigation tab`);
      await agent.aiAssert(`The "${tab}" tab is now the active/selected tab`);
    }
  });
});
