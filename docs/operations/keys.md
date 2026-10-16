---
title: "Keys and expiry"
weight: 10
description: "Bootstrap key, working key and per-CR pre-auth keys: where they live, how long, and how rotation works."
---

| Key | Where | Lifetime | Rotation |
| --- | --- | --- | --- |
| Bootstrap API key | Secret `headscale-bootstrap` (yours) | as created | manual — replace the Secret before it expires; the operator only reads it |
| Working API key | Secret `corp-apikey` (operator) | `apiKeyLifetime` (720h) | automatic at half-life, verified before the old one is expired |
| Pre-auth key per CR | Secret `<cr>-authkey` (operator) | `authKeyLifetime` (168h) | automatic at half-life, immediately when the control server or the effective tag changes (the agent pod restarts and re-registers); a restarted agent re-registers with it |

```sh
kubectl get tailnet corp -o jsonpath='{.status.apiKeyExpiresAt}'      # working key
# 2026-10-28T12:00:00Z
```

Metrics: `tailnet_apikey_expires_seconds`, `tailnetegress_authkey_expires_seconds`,
`tailnetingress_authkey_expires_seconds` — alert when they stop rising after a rotation was due. An
expired **bootstrap** key prevents recovery when the working key is absent or expired.
Ordinary half-life rotation uses the still-valid working key, not the bootstrap key.
