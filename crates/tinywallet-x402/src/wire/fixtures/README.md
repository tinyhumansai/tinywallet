# Live x402 challenge fixtures

Decoded `PAYMENT-REQUIRED` headers captured from twitr.sh on 2026-11-12. Both
requests are free: a 402 is answered before anything is paid or signed.

- `twitr-upto-challenge.json` — the volume tool challenge. It offers only the
  `upto` scheme on Base, with Permit2 `extra` fields, a per-requirement
  `extensions` object and the top-level `eip2612GasSponsoring` declaration.

  ```sh
  curl -s -D - -o /dev/null -X POST https://twitr.sh/api/tools/x_search \
    -H 'content-type: application/json' -d '{"resultsLimit":3,"query":"x"}' \
    | grep -i ^payment-required | cut -d' ' -f2- | tr -d '\r' | base64 -d
  ```

- `twitr-siwx-challenge.json` — the account-linking challenge. `accepts` is
  empty; the server asks only for the `sign-in-with-x` extension.

  ```sh
  curl -s -i -X POST https://twitr.sh/api/x-accounts/start \
    -H 'content-type: application/json' -d '{"username":"x"}' \
    | grep -i ^payment-required | cut -d' ' -f2- | tr -d '\r' | base64 -d
  ```

The SIWX fixture's `expirationTime` is in the past by the time tests run, so
tests that sign it pass an explicit clock inside its validity window.
