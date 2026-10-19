import { defineConfig } from "vitest/config";

// JSX is compiled for @opentui/solid (OpenCode's TUI renderer), not React.
// The automatic runtime emits imports from this package's jsx-runtime.
export default defineConfig({
  oxc: {
    jsx: {
      runtime: "automatic",
      importSource: "@opentui/solid",
    },
  },
});
