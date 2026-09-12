# Tasks: serialized, self-correcting zone writes

Spec: `docs/serialized-zone-writes-spec.md`

- [x] T1 mijn.host client becomes stateless (GET/PUT only), logs every call.
- [x] T2 `zone` package: payload rule with tests.
- [x] T3 `zone` package: Lease-based per-zone lock with tests.
- [x] T4 `zone` package: ConfigMap state store with expiry and tests.
- [x] T5 `zone` package: reconciler (Present, CleanUp, Sweep) with tests.
- [x] T6 Solver uses the reconciler, logs request context, resolves trigger
      context (Challenge -> Order -> Certificate) best effort.
- [x] T7 Startup and periodic sweep wired into the server lifecycle.
- [x] T8 Settings from env vars with defaults.
- [x] T9 Helm chart: RBAC, downward API env, new values.
- [x] T10 README: replace "known limitation" section, document new values and
      what the logs show.
- [x] T11 go vet, go test, golangci-lint clean.
