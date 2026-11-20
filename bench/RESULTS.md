# Raspberry Pi benchmark results

Record every measurement here with the date, the ExecuTorch window, and the git
commit.  Do not "optimize" anything without a number in this file.

## How to run

```bash
# capture/extraction, detector, classifier + SHAP
python -m bench.bench_stages --pcap /data/Friday.pcap --max-alerts 50

# LLM backend (ExecuTorch on the Pi)
python -m bench.bench_llm --rows 200 --repeats 5

# one correct sentence from the .pte before wiring it in
python -m bench.llm_smoke
```

## Expected ExecuTorch memory

| Window | KV cache | Weights (approx) |
| --- | --- | --- |
| 2k | 128 MiB | ~0.96 GB |
| **4k (default)** | **256 MiB** | **~0.96 GB** |
| 8k | 512 MiB | ~0.96 GB |
| 16k | 1 GiB | ~0.96 GB |
| 32k | 2 GiB | ~0.96 GB |

## Measurements

_No measurements recorded yet.  Run the commands above on the Pi and replace
this table; keep the date, window, and commit._

| Date | Commit | Window | Stage | Result |
| --- | --- | --- | --- | --- |
| — | — | 4k | capture -> features | not measured |
| — | — | 4k | detector per flow | not measured |
| — | — | 4k | classifier + SHAP per alert | not measured |
| — | — | 4k | LLM first call (load) | not measured |
| — | — | 4k | LLM steady-state call | not measured |
| — | — | 4k | LLM process RSS | not measured |
| — | — | 4k | RAM / CPU temperature under replay | not measured |
