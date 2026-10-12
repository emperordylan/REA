import { expect, it } from "vitest";

import { analyzeJavaScriptSemantics } from "./javascriptSemanticAnalysis.js";

it.each([
  `const fs = require("node:fs"); const cp = require("node:child_process");
   const timers = require("node:timers"); const http = require("node:http");
   const read = fs.readFileSync; const launch = cp.spawn;
   const schedule = timers.setTimeout; const get = http.get;`,
  `const fs = require("fs"); const { readFileSync: read } = fs;
   const { spawn: launch } = require("child_process");
   const { setTimeout: schedule } = require("timers");
   const { get } = require("http");`,
])("recovers builtin effects from CommonJS provenance: %s", (declarations) => {
  const ir = analyzeJavaScriptSemantics(`${declarations}
    const text = read("config.json", "utf8");
    const stream = fs.createReadStream("config.json"); stream.destroy();
    const child = launch("tool", []); child.kill("SIGTERM");
    const timer = schedule(callback, 10); clearTimeout(timer);
    get("http://example.test");
  `);
  expect(ir.configurationOperations).toMatchObject([
    { kind: "file", key: "config.json" },
  ]);
  expect(
    ir.resourceOperations.map(({ kind, method }) => ({ kind, method })),
  ).toEqual([
    { kind: "acquire", method: "createReadStream" },
    { kind: "release", method: "destroy" },
  ]);
  expect(ir.childProcessSpawns).toMatchObject([
    { method: "spawn", command: "tool" },
  ]);
  expect(ir.childProcessInteractions).toMatchObject([
    { kind: "signal", signalName: "SIGTERM" },
  ]);
  expect(
    ir.timerOperations.map(({ kind, method }) => ({ kind, method })),
  ).toEqual([
    { kind: "schedule", method: "setTimeout" },
    { kind: "cancel", method: "clearTimeout" },
  ]);
  expect(ir.requestOperations).toMatchObject([
    { method: "get", endpoint: "http://example.test" },
  ]);
});

it("does not promote ambiguous or non-namespace CommonJS origins to builtin effects", () => {
  const ir = analyzeJavaScriptSemantics(`
    const fake = require("./fs.js"); fake.readFileSync("external");
    const absentDefault = require("node:fs").default; absentDefault.readFileSync("default");
    const { constants } = require("node:fs"); constants.createReadStream("nested");
    let replaced = require("node:fs"); replaced = other; replaced.readFileSync("replaced");
    const mixed = condition ? require("node:fs") : other; mixed.readFileSync("mixed");
    function shadowed(require) { const fs = require("node:fs"); fs.readFileSync("shadowed"); }
  `);
  expect(ir.configurationOperations).toEqual([]);
  expect(ir.resourceOperations).toEqual([]);
});

it("does not assign built-in APIs to unrelated or shadowed bindings", () => {
  const ir = analyzeJavaScriptSemantics(`
    import fs from "./fs.js";
    import { constants as constantsFs } from "node:fs";
    fs.createReadStream("config.json");
    constantsFs.createReadStream("config.json");
    function run(fs) { fs.createReadStream("config.json"); }
  `);

  expect(ir.resourceOperations).toEqual([]);
});
