import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

// Inject the package version at build time so the User-Agent is versioned
// without the bundle reading package.json at runtime (browsers can't).
const { version } = JSON.parse(readFileSync("./package.json", "utf8")) as {
  version: string;
};

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  target: "es2022",
  define: {
    __PKG_VERSION__: JSON.stringify(version),
  },
});
