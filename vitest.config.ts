import { defineProject } from "vitest/config"

export default defineProject({
  test: {
    name: "verify",
    environment: "node",
    testTimeout: 30_000,
  },
})
