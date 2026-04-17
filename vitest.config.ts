import { defineConfig } from "vitest/config";

// Plain vitest config for unit tests that don't touch the Workers runtime.
// hmac.ts uses only web-standard crypto.subtle, so we can test it in Node's
// built-in Web Crypto API (Node 20+). The Worker fetch handler (worker.ts)
// should be exercised via `wrangler dev` + curl, or via miniflare in a
// separate integration harness — both are out of scope for unit tests.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
