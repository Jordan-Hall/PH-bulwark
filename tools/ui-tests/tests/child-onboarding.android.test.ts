import { afterAll, beforeAll, describe, it } from "vitest";

/**
 * The SAME child onboarding journey, but against a real Android device/emulator
 * over adb via `@midscene/android`. This validates the real native shell (the
 * Android app + its OS services), not just the shared RSX.
 *
 * Uses the documented Android SDK API
 * (https://midscenejs.com/android-api-reference.html):
 *   import { agentFromAdbDevice, getConnectedDevices } from "@midscene/android";
 * and free-form actions via `aiAct` (the `aiAction` name is deprecated).
 *
 * The suite is SKIPPED unless `ANDROID_SERIAL` is set; if it is set but no device
 * is reachable, it fails loudly in setup (rather than passing silently). It never
 * blocks the web path.
 *
 * Prereqs (see README):
 *   - adb on PATH; USB debugging on; the device unlocked + "stay awake".
 *   - the child app installed: dx build / sideload the platform/android APK.
 *   - CHILD_ANDROID_PACKAGE = co.predatorhunters.bulwark (default).
 *   - MIDSCENE_MODEL_* (vision model) configured in .env.
 */

const SERIAL = process.env.ANDROID_SERIAL?.trim();
const PACKAGE = process.env.CHILD_ANDROID_PACKAGE?.trim() || "co.predatorhunters.bulwark";

// Only run when a serial is provided (keeps CI / device-less runs green).
const run = SERIAL ? describe : describe.skip;

run("child onboarding (android)", () => {
  let agent: any;

  beforeAll(async () => {
    let mod: any;
    try {
      mod = await import("@midscene/android");
    } catch {
      throw new Error(
        "@midscene/android is not installed. Run `npm install` in tools/ui-tests.",
      );
    }
    const { agentFromAdbDevice, getConnectedDevices } = mod;

    const devices = await getConnectedDevices();
    if (!devices || devices.length === 0) {
      throw new Error(
        "no adb devices connected — run `adb devices -l` and check USB debugging.",
      );
    }

    // `aiActionContext` is global guidance the vision agent applies to every step
    // — here, to confirm the native permission dialogs the journey triggers.
    agent = await agentFromAdbDevice(SERIAL, {
      autoDismissKeyboard: true,
      aiActionContext:
        "This is the PH Bulwark child-safety setup on Android. If a system dialog " +
        "appears (Accessibility service, VPN connection request, or device-admin), " +
        "allow/confirm it, then return to the app.",
    });

    // Launch the installed native child app.
    await agent.launch(PACKAGE);
  }, 240_000);

  afterAll(async () => {
    await agent?.destroy?.().catch(() => {});
  });

  it("walks the child setup journey to 'Protection is active'", async () => {
    await agent.aiAssert('The "PH Bulwark" brand / shield is visible');
    await agent.aiAct('tap the primary "Begin" or "Get started" button');

    await agent.aiAct('tap the "I understand" button to continue past the explanation');

    // Each grant may launch a native OS permission dialog — aiAct + the global
    // aiActionContext handle confirming it.
    await agent.aiAct(
      'grant the first permission (Accessibility / chat safety) by tapping its Grant/Turn-on button, confirming any system dialog',
    );
    await agent.aiAct(
      'grant the next remaining permission (network filtering / VPN), accepting the VPN connection request dialog',
    );
    await agent.aiAct(
      'grant the last remaining permission (stay-on / device admin), confirming any system dialog',
    );

    await agent.aiAct('tap the enabled "Continue" button');

    await agent.aiInput("ABC123", "the pairing-code input field");
    await agent.aiAct('tap the "Connect" or "Pair this device" button');

    await agent.aiAssert(
      'The screen indicates protection is active or the device is paired',
    );
  });
});
