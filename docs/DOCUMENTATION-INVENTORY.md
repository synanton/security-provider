# Security Provider documentation inventory

**Reviewed:** 2026-10-21. Scope covers the repository entry point, mdBook
navigation, security posture, implementation plan, API/runbook, threat model,
and ADRs.
**Parent tracker:** [platform #368](https://github.com/synanton/platform/issues/368); **component workstream:** [security-provider #5](https://github.com/synanton/security-provider/issues/5).

| Document | Classification | Disposition / action |
|---|---|---|
| [`../README.md`](../README.md) | Current / repository status and entry point | Clarified that current signed HS256 contexts are internal; tenant-bound browser token issuance is target work (#340, repo #3). Maturity table remains evidence-gated. |
| [`index.md`](index.md), [`SUMMARY.md`](SUMMARY.md) | Current / docs navigation | Keep as mdBook entry and table of contents; README now links the inventory. |
| [`design.md`](design.md), [`architecture.md`](architecture.md) | Current / implementation contract and architecture | Retain; use with the README and platform design references, not as proof of production rollout. |
| [`IMPLEMENTATION.md`](IMPLEMENTATION.md) | Current / phase plan | Corrected stale gate language and recorded that Phase 1 code exists while formal B0/G0 and production gates remain open; marks issuer, identity, and platform-enforcement follow-ups. |
| [`api.md`](api.md), [`runbook.md`](runbook.md) | Current / operating and API docs | Retain; key setup and service operation instructions remain authoritative for implemented endpoints/configuration. |
| [`threat-model.md`](threat-model.md) | Current / security analysis | Retain as threat-model source; approval/review state must not be inferred from implementation status. |
| [`proposal.md`](proposal.md) | Historical proposal / superseded as implementation authority | Retain with superseded notice; its original sequencing statements are historical and do not describe current gate or implementation state. |
| [`adr/`](adr/) | Decision history / normative where accepted | Retain; accepted ADRs explain implementation boundaries; proposed ADR-003 remains proposed and does not imply a ratified policy. |
| Platform [shared security model](https://github.com/synanton/platform/blob/main/docs/security/security-model.md), [#340](https://github.com/synanton/platform/issues/340), [repo #3](https://github.com/synanton/security-provider/issues/3) | Cross-repo canonical contract / work tracking | Link for current token-issuer decision/status. Platform demo header/body rejection is not evidence of issuer completion or platform-wide data-layer enforcement (#339). |

No decision history was deleted. The vocabulary used in current-status claims
is Proposed, Approved (design), Contract frozen, In progress, Implemented,
Validated (with scope/evidence/date), and Superseded.
