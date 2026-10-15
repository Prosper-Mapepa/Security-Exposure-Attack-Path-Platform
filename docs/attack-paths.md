# Attack paths

The environment is a directed graph.

Nodes come from assets plus a synthetic Internet node and one node per open vulnerability. Edges are either analyst-defined relationships or system edges derived from exposure and foreign keys:

- Internet `CONNECTS_TO` a public or internet-facing asset
- An asset `EXPOSES` its open vulnerability
- A vulnerability continues along the asset's `CAN_ACCESS`, `ASSUMES_ROLE`, `AUTHENTICATES_TO`, `CONNECTS_TO`, and `DEPENDS_ON` edges
- Cloud accounts contain their resources and clusters contain their workloads

Discovery is a depth-limited walk from Internet or public nodes. A path is kept only when it includes a vulnerability and reaches a sensitive node: a database, a privileged identity, critical criticality, or confidential/restricted data.

```text
score = clamp(0, 100,
  entry exposure
  + vulnerability risk * 0.4
  + privilege edges * 8
  + sink criticality
  + sensitive-data points
  - extra-hop penalty
)
```

Each stored node keeps the explanation used by the UI. Paths are recomputed by the worker after a scan and when an analyst calls `POST /api/attack-paths/rebuild`. The engine does not invent edges that were not stored.

A finding receives attack-path risk only when its vulnerability node lies on a kept path. The sensitive-path factor is set only when that path's sink is sensitive.
