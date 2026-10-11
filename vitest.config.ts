import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

// Mirror tsup's build-time version injection so tests see the real version.
const { version } = JSON.parse(readFileSync("./package.json", "utf8")) as {
  version: string;
};

export default defineConfig({
  define: {
    __PKG_VERSION__: JSON.stringify(version),
  },
  test: {
    globals: true,
    include: ["tests/**/*.test.ts"],
  },
});
