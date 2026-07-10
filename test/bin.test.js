const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

test("packaged CLI entrypoint starts the application", () => {
  const binPath = path.join(__dirname, "..", "bin", "update.js");
  const environment = { ...process.env };
  delete environment.NPM_HOST;
  delete environment.NPM_EMAIL;
  delete environment.NPM_PASSWORD;

  const result = spawnSync(process.execPath, [binPath], {
    encoding: "utf8",
    env: environment,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Usage: npm-ssl-updater/);
  assert.match(result.stdout, /--password-stdin/);
});
