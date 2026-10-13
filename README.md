# @pactlo/verify

Checks Pactlo evidence offline, without trusting Pactlo.

```sh
npx @pactlo/verify certificate.pdf              # the bundle a certificate of completion carries
npx @pactlo/verify certificate.pdf update.json  # plus the latest proof from pactlo.com/verify
npx @pactlo/verify bundle.json                  # a bundle on its own
npx @pactlo/verify bundle.json --json           # machine-readable report
```

Exit codes: `0` verified, `3` incomplete (newest events not timestamped yet),
`1` failed, `2` usage error.

The same code runs in browsers: pactlo.com/verify computes a file's SHA-256
on your device (the file is never uploaded) and checks Pactlo's receipt for
it. It trusts only the keys and timestamp roots pinned in `src/trust.ts`. The
formats and every hash are specified in [SPEC.md](SPEC.md).

License: Apache-2.0.
