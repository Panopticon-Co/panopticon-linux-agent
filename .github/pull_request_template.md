## Summary

<!-- One or two sentences: what does this PR do and why? -->

## Changes

<!-- Bulleted list of the concrete changes. -->

## Testing

<!-- Commands run, e.g. ctest --test-dir build --output-on-failure, e2e suites exercised, sanitizer build. -->

## Security Impact

<!-- Does this touch the closed response action set, the isolation privilege boundary
     (CAP_NET_ADMIN helper), command validation/replay/expiry, or file collection/quarantine
     jails? If none, say "None". -->

## Documentation

<!-- Which docs were updated (README.md, ARCHITECTURE.md, RESPONSE.md, CONFIGURATION.md,
     TELEMETRY.md, TESTING.md, SECURITY.md, docs/adr/*)? If none needed, say why. -->

## Cross-Repository Impact

<!-- Does this change the event/command wire contract shared with panopticon-manager,
     panopticon-contracts, panopticon-agent, or panopticon-detection-engine? See
     docs/CROSS_REPO_IMPACT.md. If none, say "None". -->

## Checklist

- [ ] Tests added/updated for the change
- [ ] Existing tests pass (`ctest --test-dir build --output-on-failure`)
- [ ] Documentation updated
- [ ] Security implications considered
- [ ] Shared contracts updated if applicable (panopticon-contracts, docs/CROSS_REPO_IMPACT.md)
- [ ] Cross-repo compatibility checked (Manager, Windows agent, Detection Engine)
- [ ] No unrelated changes
