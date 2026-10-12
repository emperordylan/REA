import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

describe("JavaScript static analysis findings", () => {
  it("does not infer a webpack push from a dynamic computed key", () => {
    const analysis = analyzeJavaScriptStaticSource(`
      const push = "push";
      const arr = {};
      arr[push]([[1], { 1: function () {} }]);
    `);
    expect(analysis.bundler_registrations).toEqual([]);
  });

  it("retains every static reference and Electron property in large literals", () => {
    const names = Array.from({ length: 10_001 }, (_, index) => `key${index}`);
    const source = [
      'const { BrowserWindow, contextBridge } = require("electron");',
      ...names.map(
        (name, index) => `import value${index} from "./${name}.js";`,
      ),
      `new BrowserWindow({ webPreferences: { ${names.map((name) => `${name}: true`).join(", ")} } });`,
      `contextBridge.exposeInMainWorld("api", { ${names.map((name) => `${name}: () => true`).join(", ")} });`,
      `const { ${names.join(", ")} } = require("./addon.node");`,
    ].join("\n");
    const analysis = analyzeJavaScriptStaticSource(source);

    expect(analysis.parse_status).toBe("complete");
    expect(analysis.references).toHaveLength(10_003);
    expect(analysis.electron.browser_windows[0]?.web_preferences).toHaveLength(
      10_001,
    );
    expect(analysis.electron.context_bridge_apis[0]?.members).toHaveLength(
      10_001,
    );
    expect(analysis.electron.native_addon_bindings[0]?.members).toHaveLength(
      10_001,
    );
  });

  it.each([false, true])(
    "retains Electron findings after many ordinary container writes (selected slot: %s)",
    (mutateElectron) => {
      const writes = Array.from(
        { length: 1_001 },
        (_, index) => `box.key${index}=${index};`,
      );
      const analysis = analyzeJavaScriptStaticSource(
        [
          'const e=require("electron"); const box={};',
          ...(mutateElectron ? ["box.ipc=e.ipcMain;"] : []),
          ...writes,
          ...(mutateElectron ? ["delete box.ipc.on;"] : []),
          'e.ipcMain.handle("direct:retained",event=>event.sender.copy());',
          "function handle(channel,handler){e.ipcMain.handle(channel,handler);}",
          'handle("wrapped:retained",event=>event.sender.copy());',
          'e.ipcMain.on("selected:method",event=>event.sender.copy());',
        ].join("\n"),
      );
      expect(analysis.parse_error_count).toBe(0);
      expect(
        analysis.limitations.some((limitation) =>
          limitation.includes("resource budget"),
        ),
      ).toBe(false);
      expect(
        analysis.electron.ipc.filter(({ channel }) => channel !== null),
      ).toMatchObject([
        { channel: "direct:retained", operation: "handle" },
        ...(mutateElectron
          ? []
          : [{ channel: "selected:method", operation: "on" }]),
        { channel: "wrapped:retained", operation: "handle" },
      ]);
      expect(analysis.electron.call_paths).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            channel: "wrapped:retained",
            terminal: "ipc-event.sender.copy",
          }),
        ]),
      );
    },
  );
});
