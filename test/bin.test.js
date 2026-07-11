const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { mkdtempSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const path = require("node:path");

function environmentWithoutNpmCredentials() {
  const environment = { ...process.env };
  delete environment.NPM_HOST;
  delete environment.NPM_EMAIL;
  delete environment.NPM_PASSWORD;
  return environment;
}

test("importing the application does not load credentials from .env", () => {
  const applicationPath = path.join(__dirname, "..", "update_ssl.js");
  const script = [
    `require(${JSON.stringify(applicationPath)});`,
    "const names = ['NPM_HOST', 'NPM_EMAIL', 'NPM_PASSWORD'];",
    "console.log(names.some((name) => process.env[name]));",
  ].join(" ");
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: path.join(__dirname, ".."),
    encoding: "utf8",
    env: environmentWithoutNpmCredentials(),
    timeout: 5000,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "false");
});

test("packaged CLI entrypoint shows help without loading the project .env", () => {
  const binPath = path.join(__dirname, "..", "bin", "update.js");
  const workingDirectory = mkdtempSync(path.join(tmpdir(), "npm-ssl-updater-test-"));

  try {
    const result = spawnSync(process.execPath, [binPath], {
      cwd: workingDirectory,
      encoding: "utf8",
      env: environmentWithoutNpmCredentials(),
      timeout: 5000,
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Usage: npm-ssl-updater/);
    assert.match(result.stdout, /--password-stdin/);
  } finally {
    rmSync(workingDirectory, { recursive: true, force: true });
  }
});

test("npm package includes the executable and runtime files", () => {
  const repositoryRoot = path.join(__dirname, "..");
  const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: environmentWithoutNpmCredentials(),
    timeout: 15000,
  });

  assert.equal(result.status, 0, result.stderr);

  const [packageMetadata] = JSON.parse(result.stdout);
  const packagedFiles = packageMetadata.files.map(({ path: filePath }) => filePath);

  assert.ok(packagedFiles.includes("bin/update.js"));
  assert.ok(packagedFiles.includes("update_ssl.js"));
  assert.ok(packagedFiles.includes("package.json"));
});
