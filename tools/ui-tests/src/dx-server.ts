import { spawn, type ChildProcess } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
// tools/ui-tests/src -> repo root is four levels up.
const DEFAULT_REPO_ROOT = resolve(HERE, "..", "..", "..");

export function repoRoot(): string {
  return process.env.BULWARK_REPO_ROOT?.trim() || DEFAULT_REPO_ROOT;
}

export interface DxServer {
  url: string;
  stop: () => Promise<void>;
}

/**
 * Boot `dx serve --platform web` for one of the Dioxus apps and resolve once the
 * dev server answers on http://127.0.0.1:<port>. Cross-platform: `dx` is invoked
 * via the OS shell so Windows finds `dx.exe` on PATH. No bash-isms.
 */
export async function serveDioxusWeb(opts: {
  appDir: string; // e.g. "apps/child"
  port: number;
}): Promise<DxServer> {
  const cwd = resolve(repoRoot(), opts.appDir);
  const url = `http://127.0.0.1:${opts.port}`;

  const child: ChildProcess = spawn(
    "dx",
    [
      "serve",
      "--platform",
      "web",
      "--port",
      String(opts.port),
      "--addr",
      "127.0.0.1",
      "--open",
      "false",
    ],
    {
      cwd,
      shell: true, // lets Windows resolve dx.exe / the .cmd shim
      stdio: ["ignore", "inherit", "inherit"],
      env: process.env,
    },
  );

  child.on("error", (err) => {
    console.error(`[dx-server] failed to spawn dx in ${cwd}:`, err);
  });

  await waitForHttp(url, { timeoutMs: 180_000, child });

  return {
    url,
    stop: () => stopProcess(child),
  };
}

async function waitForHttp(
  url: string,
  { timeoutMs, child }: { timeoutMs: number; child: ChildProcess },
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(
        `dx serve exited early (code ${child.exitCode}) before ${url} was reachable. ` +
          `Check that the app builds for the web target (see README).`,
      );
    }
    try {
      const res = await fetch(url, { redirect: "manual" });
      // Any HTTP response (even 404 for a sub-path) means the server is up.
      if (res.status > 0) return;
    } catch (e) {
      lastErr = e;
    }
    await delay(1500);
  }
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${url}. Last error: ${String(lastErr)}`,
  );
}

async function stopProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.killed) return;
  await new Promise<void>((resolveStop) => {
    child.once("exit", () => resolveStop());
    // On Windows, killing the shell parent does not always reap the dx child
    // tree; SIGTERM then a hard SIGKILL fallback covers both platforms.
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null && !child.killed) {
        try {
          child.kill("SIGKILL");
        } catch {
          /* already gone */
        }
      }
      resolveStop();
    }, 4000);
  });
}
