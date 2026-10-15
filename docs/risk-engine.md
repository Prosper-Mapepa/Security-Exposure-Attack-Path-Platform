# Risk engine

Formula version `1.0.0`.

Each factor is normalized to 0–10. The score is the weighted sum, expressed as 0–100, minus the compensating-control contribution, then clamped.

```text
score = clamp(0, 100,
  100 * (
    technical * 0.22 +
    exploitability * 0.14 +
    business * 0.16 +
    exposure * 0.14 +
    authentication * 0.08 +
    privilege * 0.06 +
    data * 0.08 +
    age * 0.04 +
    attackPath * 0.08
  ) - controls * 0.15 * 100
)
```

- Technical severity uses CVSS when the scanner provides it. Otherwise critical=9.5, high=7.5, medium=5, low=2.5, info=0.
- Exploitability uses a public-exploit reference when one is present. With no threat-intel feed, it is estimated from severity and the explanation says so.
- Business impact follows asset criticality.
- Exposure is 10 for internet-facing or public assets.
- Missing authentication scores higher than required authentication.
- Privilege required of `NONE` scores higher than `HIGH`.
- Data sensitivity, age (180 days reaches 10), and attack-path membership add context.
- Compensating controls come from asset metadata `compensatingControlScore` (0–10) and reduce the result.

Bands: 80 critical, 60 high, 40 medium, 15 low, otherwise info.

Organizations can replace weights through `PUT /api/risk-model`. The stored explanation lists every factor, its weight, its contribution, and the reason.
