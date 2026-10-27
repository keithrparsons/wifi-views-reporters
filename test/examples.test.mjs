import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const example = name => readFileSync(new URL(`../src/examples/${name}`, import.meta.url), "utf8");

const reports = [
  ["Mac", require("../src/wdutil.js"), "mac-wdutil.txt"],
  ["Windows", require("../src/netsh.js"), "windows-netsh.txt"],
  ["Nearby", require("../src/lswifi.js"), "nearby-lswifi.json"],
];

for (const [name, tool, file] of reports) {
  const report = tool.analyze(tool.parse(example(file)));

  test(`${name} report: the example makes a report`, () => {
    assert.ok(!report.empty);
    assert.match(tool.render(report, { redact: false, logo: "" }), /Example-Home/);
  });

  test(`${name} report: hiding identifying details hides the network name`, () => {
    assert.doesNotMatch(tool.render(report, { redact: true, logo: "" }), /Example-Home/);
  });
}
