# legacy/

Empty placeholder for the moment. Prior contents (pre-refactor per-IP C engine
and the frozen C-detection parity oracle) have been deleted — the Python
detection brain is now the single source of truth and has intentionally
diverged from the old C math (Welford-true variance, n=10 burst window, ±6σ
winsorisation). See git history for the retired sources.
