# Architecture decisions

Short records of decisions that are expensive to rediscover. Read the relevant
one before changing the behaviour it explains — each says what was tried and
what it cost.

| ADR | Decision |
|---|---|
| [0001](0001-protocol-source-of-truth.md) | The wire format is read from formstr-drive's source, at a pinned SHA |
| [0002](0002-deliberate-parity.md) | Read leniently, write the spec: how the SDK meets the app's file shape |
| [0003](0003-drive-key-mint-hazard.md) | The Drive Key mint hazard, and why `empty-confirmed` is so hard to earn |
| [0004](0004-scope.md) | What the SDK covers, and what it deliberately leaves out |

The wire format itself lives in [`../protocol.md`](../protocol.md).
