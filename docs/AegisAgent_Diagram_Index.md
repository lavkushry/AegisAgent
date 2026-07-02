# Diagram Index

**One sentence:** every diagram in the documentation, as diagram-as-code (Mermaid), with the page that explains it.

Sources live in [`docs/diagrams/`](https://github.com/lavkushry/AegisAgent/tree/main/docs/diagrams) as `.mmd` files (render with any Mermaid tool: `npx -y @mermaid-js/mermaid-cli -i <file>.mmd -o <file>.svg`, mermaid.live, or your IDE). The same diagrams are embedded inline in their explanation pages, and the docs site renders them natively. The layered system diagrams derive from [architecture-map.json](architecture-map.json) — update the JSON first, diagrams second. The database ERD is maintained inline in [database-schema.md](database-schema.md).

| # | Diagram | Source | Explained in | Status of subject |
|---|---|---|---|---|
| 0 | Simple system picture | [simple-system.mmd](diagrams/simple-system.mmd) | [The_One_Minute_Tour.md](The_One_Minute_Tour.md) | Implemented |
| 1 | Full system architecture (6 layers) | [layered-architecture.mmd](diagrams/layered-architecture.mmd) | [Architecture_Overview.md](Architecture_Overview.md) | mixed (✅/📐 marked) |
| 2 | Known agent action flow | [known-agent-flow.mmd](diagrams/known-agent-flow.mmd) | [flows/Known_Agent_Flow.md](flows/Known_Agent_Flow.md) | ✅ |
| 3 | Anonymous agent cage flow | [unknown-agent-flow.mmd](diagrams/unknown-agent-flow.mmd) | [flows/Unknown_Agent_Cage_Flow.md](flows/Unknown_Agent_Cage_Flow.md) | 🟡/📐 |
| 4 | Approval lifecycle (state machine) | [approval-flow.mmd](diagrams/approval-flow.mmd) | [components/Approval_Engine.md](components/Approval_Engine.md) | ✅ |
| 5 | Receipt hash chain | [receipt-flow.mmd](diagrams/receipt-flow.mmd) | [flows/Receipt_Flow.md](flows/Receipt_Flow.md) | ✅ |
| 6 | SOC incident creation | [soc-incident-flow.mmd](diagrams/soc-incident-flow.mmd) | [components/SOC_Engine.md](components/SOC_Engine.md) | ✅ |
| 7 | Ban / quarantine ladder | [ban-quarantine-flow.mmd](diagrams/ban-quarantine-flow.mmd) | [flows/Ban_Quarantine_Flow.md](flows/Ban_Quarantine_Flow.md) | 🟡 |
| 8 | Control command protocol | [control-command-flow.mmd](diagrams/control-command-flow.mmd) | [flows/Control_Command_Flow.md](flows/Control_Command_Flow.md) | 🟡/📐 |
| 9 | Egress proxy flow | [egress-flow.mmd](diagrams/egress-flow.mmd) | [components/Egress_Proxy.md](components/Egress_Proxy.md) | 📐 |
| 10 | Tool broker flow | [tool-broker-flow.mmd](diagrams/tool-broker-flow.mmd) | [components/Tool_Broker.md](components/Tool_Broker.md) | 📐 |
| 11 | SDK fail-closed decision tree | [sdk-fail-closed.mmd](diagrams/sdk-fail-closed.mmd) | [fail-closed-behavior.md](fail-closed-behavior.md), [components/SDK.md](components/SDK.md) | ✅ |
| 12 | Tenant / auth flow | [tenant-auth-flow.mmd](diagrams/tenant-auth-flow.mmd) | [production-hardening.md](production-hardening.md) | ✅ |
| 13 | Database ERD | inline | [database-schema.md](database-schema.md) | ✅ |
| 14 | Event ingestion pipeline | [event-ingestion-pipeline.mmd](diagrams/event-ingestion-pipeline.mmd) | [components/SOC_Engine.md](components/SOC_Engine.md), [event-schema.md](event-schema.md) | ✅ |
| 15 | Deployment topology | [deployment-topology.mmd](diagrams/deployment-topology.mmd) | [deployment-guide.md](deployment-guide.md) | ✅ |
| 16 | CI/CD pipeline | [cicd-pipeline.mmd](diagrams/cicd-pipeline.mmd) | [Repo_Knowledge_Map.md](Repo_Knowledge_Map.md) §9 | ✅ |
| 17 | Threat-model trust boundaries | [trust-boundaries.mmd](diagrams/trust-boundaries.mmd) | [Architecture_Overview.md](Architecture_Overview.md) §5, [AegisAgent_Threat_Model.md](AegisAgent_Threat_Model.md) | ✅ |
| 18 | MCP defense flow | [mcp-defense-flow.mmd](diagrams/mcp-defense-flow.mmd) | [components/MCP_Gateway.md](components/MCP_Gateway.md) | ✅ |

## Interactive alternative

The [architecture explorer](explorer/index.html) renders the full system map interactively (3D layers, flow toggles, click-to-inspect), driven by [architecture-map.json](architecture-map.json). It degrades to a 2D canvas without WebGL, and these static diagrams remain the accessible fallback.

## Conventions

- Diagram-as-code first; no binary-only diagrams.
- `*` suffix inside a diagram = planned/not implemented component.
- Every diagram carries a `%%` header comment naming its explanation page.
- Adding a diagram: put the `.mmd` here, embed it in the owning doc, add a row to this table (validated by `scripts/validate-docs.mjs`).
