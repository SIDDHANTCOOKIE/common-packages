import { defineConfig } from "tsup";

export default defineConfig({
  // The local-relay adapter is a separate entry so importing the SDK never pulls in the optional peer.
  entry: { index: "src/index.ts", "local-relay": "src/local-relay.ts" },
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  target: "es2022",
  external: ["@formstr/local-relay"],
});
