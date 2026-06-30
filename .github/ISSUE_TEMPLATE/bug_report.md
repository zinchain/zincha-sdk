---
name: Bug report
about: Report a non-security bug in the Zincha SDKs, CLI, or public API surface
title: "[Bug]: "
labels: ["bug"]
assignees: []
---

<!--
⚠️  SECURITY / EXPLOITABLE BUGS — DO NOT FILE HERE
If this report involves a vulnerability that could affect funds, consensus,
key material, signing, fund-moving transactions, or any exploitable weakness,
DO NOT open a public issue. Report it privately via a GitHub Security Advisory:

  https://github.com/zinchain/zincha-sdk/security/advisories/new

Public issues are for low/medium-severity, non-exploitable bugs only. Both
paths feed the same review process and the same bug-bounty ledger.
See the bounty program at https://zincha.com/bug-bounty
-->

## Summary

<!-- One or two sentences describing the bug. Do not include exploit details. -->

## Affected surface

<!-- Tick all that apply. -->

- [ ] Rust SDK (`zincha-client` / `zincha-primitives`)
- [ ] `zincha` CLI
- [ ] TypeScript SDK (`@zincha/client`)
- [ ] Python SDK (`zincha`)
- [ ] OpenAPI spec / documented public API behavior
- [ ] Documentation
- [ ] Other (describe below)

## Environment

| Field | Value |
| --- | --- |
| SDK / CLI version | <!-- e.g. zincha 0.1.0, @zincha/client 0.1.0 --> |
| Language + runtime | <!-- e.g. Rust 1.75, Node.js 20, Python 3.11 --> |
| OS / arch | <!-- e.g. macOS 14 arm64, Ubuntu 22.04 x86_64 --> |
| Release targeted | <!-- vega / polaris / sirius / altair / lyra, or a custom --api-url --> |

## Steps to reproduce

1.
2.
3.

<!-- Include the minimal command or code snippet that triggers the bug.
     Redact any secret keys, bearer tokens, or private material. -->

```
# command or code here
```

## Expected behavior

<!-- What you expected to happen. -->

## Actual behavior

<!-- What actually happened. Include error messages and, if relevant,
     the transaction hash or request/response (with secrets redacted). -->

```
# output / logs / error here
```

## Additional context

<!-- Anything else that helps: links, screenshots, related issues. -->

---

<!--
Reminder: never paste seed phrases, raw private keys, bearer tokens, mTLS
keys, or operator certificates into a public issue. If you accidentally
expose one, rotate it immediately.
-->
