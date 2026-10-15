# TFW metrics

[![Repository size](https://img.shields.io/github/repo-size/tfw-org/tfw-metrics?label=Repository%20size&color=blue)](https://github.com/tfw-org/tfw-metrics)

This repository collects historical metrics from TFW's ClusterFuzzLite runs. It is separate from the `tfw` library and `tfw-fuzzing` corpus/report repository.

## What is collected

- `metrics/batch_fuzzers.csv`: one row per discovered fuzzer per successful batch run, including `cov`, `ft`, execution counts/rates, active corpus statistics, persistent corpus size, run ID/attempt, timestamp, and source commit SHA.
- `metrics/coverage_runs.csv`: JaCoCo line and branch coverage summary observed after a successful coverage workflow.
- `metrics/processed-runs.txt`: workflow run IDs and attempts already processed, preventing duplicate history rows.

The collector discovers fuzzers from the logs of each batch run; it does not assume a fixed number of fuzzers.

## GitHub Actions setup

Create a repository secret named `TFW_ORG_READ_TOKEN`. Use a fine-grained token with read access to Actions in `tfw-org/tfw` and read access to repository contents in `tfw-org/tfw-fuzzing`. Do not grant write access to those repositories. The workflow's built-in `GITHUB_TOKEN` writes metrics only to this repository.

The workflow polls successful completed runs every six hours and can also be started manually. It examines the most recent 100 completed runs returned by GitHub. If the project eventually generates more than 100 runs between polls, increase pagination in the workflow so older runs are not missed.

## Interpreting the data

`cov` and `ft` are libFuzzer metrics, not source-code coverage percentages. Use `coverage_runs.csv` for JaCoCo line/branch coverage. Compare each fuzzer with its own previous runs, and interpret corpus size alongside coverage rather than as a success metric by itself.
