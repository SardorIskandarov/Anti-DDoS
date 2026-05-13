# cJSON (vendored)

[cJSON](https://github.com/DaveGamble/cJSON) is Dave Gamble's
single-file, MIT-licensed JSON parser for C — ~16 KB header + ~79 KB
implementation, no external dependencies, in continuous maintenance
since 2009.

| Field        | Value                                                |
|--------------|------------------------------------------------------|
| Upstream URL | https://github.com/DaveGamble/cJSON                  |
| Version      | **1.7.18** (see `VERSION`)                           |
| Vendored on  | 2026-05-13                                           |
| License      | MIT (see `LICENSE`)                                  |

We pinned the version explicitly so the cutover from the C-coded
profile table to JSON-driven service registry is reproducible. The
upstream `master` branch may carry post-release fixes; we do NOT
track it.

**Rule: do not edit these files.** If a fix is required, update
`VERSION`, re-vendor from a different upstream tag, and document the
reason here. Local patches make the next vendor refresh painful and
defeat reproducibility.

The companion file integrity is verified at vendor time via SHA-256:

```
0578cc29132912edbc88f83207a8fc76e5db3db0605497e909a9384ef3cc474b  cJSON.h
75c51de8fa40ac9d7a99319c6330719bd692eb81c0a869265f3d4c682533f9b9  cJSON.c
a36dda207c36db5818729c54e7ad4e8b0c6fba847491ba64f372c1a2037b6d5c  LICENSE
```

Re-fetch with:

```bash
curl -fsSLO https://github.com/DaveGamble/cJSON/raw/v1.7.18/cJSON.h
curl -fsSLO https://github.com/DaveGamble/cJSON/raw/v1.7.18/cJSON.c
curl -fsSLO https://github.com/DaveGamble/cJSON/raw/v1.7.18/LICENSE
```
