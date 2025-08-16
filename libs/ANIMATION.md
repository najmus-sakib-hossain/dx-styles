Please add all these features in one go:
```md
Proper keyframe aggregation for from/via/to + animate (TODO left; ANIM lines ignored).
Forward fill-mode (forwards) integration.
Background alpha parsing (e.g. bg-white/50) not yet converted—needs color + opacity merge logic.
Gradient mesh/linear/radial/conic and scoped components not yet implemented.
Dedup of grouped state utilities into single dx-c-* now occurs only when advanced features present; simple hover(...) without child/state mix still may expand as simple utilities if no advanced markers.
```