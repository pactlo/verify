# @pactlo/verify

Checks a Pactlo evidence bundle offline, without trusting Pactlo.

```sh
npx @pactlo/verify bundle.json          # human-readable report
npx @pactlo/verify bundle.json --json   # machine-readable report
```

Exit codes: `0` verified, `3` incomplete (newest events not timestamped yet),
`1` failed, `2` usage error.

The same code runs in browsers (pactlo.com/verify checks files locally; nothing
is uploaded). It trusts only the keys and timestamp roots pinned in
`src/trust.ts`. The format and every hash are specified in [SPEC.md](SPEC.md).

License: Apache-2.0.
